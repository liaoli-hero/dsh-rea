// dsh-rea — REA (Reverse Engineer Anything) bridge for the DeepSeek Harness.
//
// Why a plugin instead of an MCP server: REA advertises 170 MCP tools whose
// combined input schema is ~1.95 MB of JSON (~490k tokens). Any MCP client
// injects every advertised schema into every model request, which is unusable
// here. A plugin owns its own tool schemas, so this bridge exposes three small
// tools that reach the same engines: the full `rea` CLI (127 commands) plus the
// REA MCP server for stateful analysis sessions, with schemas fetched on demand
// rather than pinned into the prompt.
//
// Tools:
//   rea_list  — discover capabilities (overview | commands | tools)
//   rea_cli   — run one `rea <command> [args...]` invocation
//   rea_tool  — call one REA MCP tool by name with JSON arguments
//
// @module dsh-rea

import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync } from 'node:fs'
import { writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'

/** Cordis plugin name. */
export const name = 'dsh-rea'

/** Services required before this plugin can register tools. */
export const inject = ['tools']

/** Plugin configuration. */
export const Config = z.object({
  /** Node executable used to run the REA CLI script. Empty resolves to `node` on PATH. */
  nodePath: z.string().default(''),
  /** Absolute path of rea-agents' scripts/rea.mjs. Empty auto-discovers. */
  reaEntry: z.string().default(''),
  /** Character budget for one tool result before it spills to a file. */
  maxOutputChars: z.number().default(80_000),
  /** Default ceiling for one REA invocation. */
  defaultTimeoutMs: z.number().default(1_800_000),
})

// ---- capability map --------------------------------------------------------
// Mirrors the proxy grouping so `rea_list` and `rea_tool` agree on names.

const GROUPS = {
  native: [
    'open_binary', 'close_binary', 'binary_session', 'binary_overview',
    'list_procedures', 'search_procedures', 'list_names', 'list_segments',
    'procedure_info', 'procedure_pseudo_code', 'procedure_assembly',
    'procedure_callers', 'procedure_callees', 'procedure_references',
    'xrefs', 'address_name', 'find_xrefs_to_name', 'read_bytes',
    'search_strings', 'list_strings', 'address_to_file_offset',
    'analyze_function', 'batch_decompile', 'get_call_graph', 'build_call_path',
    'trace_call_path', 'compare_functions', 'trace_feature',
  ],
  js: [
    'analyze_javascript_application', 'list_electron_targets',
    'inspect_electron_page', 'list_javascript_runtime_targets',
    'observe_javascript_runtime', 'recover_javascript_sources',
    'trace_javascript_semantics', 'compare_javascript_export_shapes',
    'trace_application_feature', 'reconcile_javascript_runtime',
  ],
  artifact: [
    'inspect_artifact', 'extract_artifact', 'inspect_pe_resources',
    'inspect_managed_artifact', 'inspect_managed_members', 'inspect_macho',
    'inspect_plist', 'inspect_binary_layout', 'inspect_firmware_regions',
    'extract_firmware', 'inspect_keyed_archive', 'inspect_signature',
    'inspect_asset_catalog', 'inspect_evm_interface',
    'project_managed_application_graph', 'compare_managed_members',
  ],
  mobile: [
    'inspect_android_package', 'inspect_android_class', 'inspect_android_method',
    'decode_android_resources', 'search_android_classes', 'trace_android_references',
    'list_adb_devices', 'list_adb_packages', 'pull_adb_package', 'pull_adb_file',
    'push_adb_file', 'read_adb_logcat', 'capture_adb_screen', 'install_adb_package',
    'start_adb_app', 'stop_adb_app', 'uninstall_adb_package',
    'project_android_application_graph', 'inspect_adb_device', 'inspect_adb_client',
  ],
  web: [
    'inspect_web_page', 'analyze_web_bundle', 'capture_web_screenshot',
    'inspect_web_network_capture', 'export_web_scripts', 'list_browser_targets',
    'observe_web_execution', 'observe_web_session', 'capture_browser_scenario',
    'trace_web_source_location', 'trace_web_module_imports', 'compare_web_captures',
  ],
  evidence: [
    'get_evidence_bundle', 'export_evidence_bundle', 'import_evidence_bundle',
    'list_unknowns', 'record_unknown', 'update_unknown', 'verify_unknown_resolution',
    'get_navigation_context', 'evaluate_reconstruction_coverage',
    'verify_reconstruction', 'correlate_static_and_runtime',
    'build_reconstruction_obligation_ledger',
  ],
  runtime: [
    'capture_process_scenario', 'capture_electron_scenario',
    'capture_native_ui_scenario', 'observe_native_calls', 'observe_native_ui',
    'trace_native_ui_action', 'trace_native_values', 'compare_process_captures',
    'compare_application_versions', 'find_changed_behavior', 'compare_artifacts',
    'compare_bundles', 'inspect_analysis_view',
  ],
}

/** tool name -> group name, first group wins. */
const TOOL_GROUP = new Map()
for (const [group, tools] of Object.entries(GROUPS)) {
  for (const tool of tools) if (!TOOL_GROUP.has(tool)) TOOL_GROUP.set(tool, group)
}

// ---- process plumbing ------------------------------------------------------

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** Resolve the REA CLI entry script, honouring an explicit override. */
function resolveReaEntry(configured) {
  if (configured) return configured
  const candidates = [
    join(process.env.APPDATA ?? '', 'npm', 'node_modules', 'rea-agents', 'scripts', 'rea.mjs'),
    join(process.env.LOCALAPPDATA ?? '', 'npm', 'node_modules', 'rea-agents', 'scripts', 'rea.mjs'),
    '/usr/local/lib/node_modules/rea-agents/scripts/rea.mjs',
    '/usr/lib/node_modules/rea-agents/scripts/rea.mjs',
  ]
  for (const candidate of candidates) if (candidate && existsSync(candidate)) return candidate
  return ''
}

/** Environment for a REA child: inherited, minus the harness session markers. */
function reaEnv() {
  const env = { ...process.env }
  for (const key of Object.keys(env)) if (key.startsWith('DSH_')) delete env[key]
  delete env.ELECTRON_RUN_AS_NODE
  return env
}

/** Resolution report used by `rea_list` and by startup diagnostics. */
function makeRuntime(config, logger) {
  const node = config.nodePath || (process.platform === 'win32' ? 'node' : 'node')
  const entry = resolveReaEntry(config.reaEntry)
  const state = {
    node,
    entry,
    ready: Boolean(entry),
    /** Lazily started `rea mcp` child. */
    child: null,
    readyPromise: null,
    buf: '',
    pending: new Map(),
    nextId: 1,
    tools: null,
    toolsError: null,
    toolCount: 0,
  }

  if (!state.ready) {
    logger?.warn?.('dsh-rea: rea-agents CLI not found; set dsh-rea config `reaEntry` to scripts/rea.mjs')
  }

  function startChild() {
    const child = spawn(node, [entry, 'mcp'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      env: reaEnv(),
    })
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')

    child.stdout.on('data', (chunk) => {
      state.buf += chunk
      let index
      while ((index = state.buf.indexOf('\n')) >= 0) {
        const line = state.buf.slice(0, index).trim()
        state.buf = state.buf.slice(index + 1)
        if (!line) continue
        let message
        try {
          message = JSON.parse(line)
        } catch {
          continue
        }
        if (message.id != null && state.pending.has(message.id)) {
          const entryPending = state.pending.get(message.id)
          state.pending.delete(message.id)
          clearTimeout(entryPending.timer)
          entryPending.resolve(message)
        }
      }
    })
    child.stderr.on('data', (chunk) => logger?.debug?.(`dsh-rea: ${String(chunk).trim().slice(0, 400)}`))
    child.on('exit', (code) => {
      logger?.debug?.(`dsh-rea: rea mcp exited (${code})`)
      for (const [, entryPending] of state.pending) {
        clearTimeout(entryPending.timer)
        entryPending.reject(new Error('REA MCP server exited'))
      }
      state.pending.clear()
      state.child = null
      state.readyPromise = null
      state.tools = null
    })
    return child
  }

  function request(method, params, timeoutMs) {
    const id = state.nextId++
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        state.pending.delete(id)
        reject(new Error(`REA MCP request timed out after ${timeoutMs} ms: ${method}`))
      }, timeoutMs)
      state.pending.set(id, { resolve, reject, timer })
      state.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
    })
  }

  /** Start and initialize the MCP child once. */
  async function ensureChild(timeoutMs) {
    if (state.readyPromise) return state.readyPromise
    state.readyPromise = (async () => {
      state.child = startChild()
      const init = await request(
        'initialize',
        {
          protocolVersion: '2025-11-25',
          capabilities: {},
          clientInfo: { name: 'dsh-rea', version: '0.1.0' },
        },
        timeoutMs,
      )
      state.child.stdin.write(
        `${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} })}\n`,
      )
      return init.result
    })().catch((error) => {
      state.readyPromise = null
      throw error
    })
    return state.readyPromise
  }

  /** Fetch and cache the advertised MCP tool list. */
  async function toolList(timeoutMs) {
    if (state.tools) return state.tools
    if (state.toolsError) throw state.toolsError
    try {
      await ensureChild(timeoutMs)
      const response = await request('tools/list', {}, timeoutMs)
      const tools = response.result?.tools ?? []
      state.tools = tools
      state.toolCount = tools.length
      return tools
    } catch (error) {
      state.toolsError = error
      throw error
    }
  }

  return { state, ensureChild, request, toolList }
}

/** One `rea <command>` CLI invocation with bounded output. */
function runCli(runtime, args, { timeoutMs, signal, maxChars }) {
  return new Promise((resolve) => {
    const child = spawn(runtime.state.node, [runtime.state.entry, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      env: reaEnv(),
    })
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')

    let stdout = ''
    let stderr = ''
    let truncated = false
    const cap = maxChars * 4

    child.stdout.on('data', (chunk) => {
      if (stdout.length < cap) stdout += chunk
      else truncated = true
    })
    child.stderr.on('data', (chunk) => {
      if (stderr.length < cap) stderr += chunk
      else truncated = true
    })

    const timer = setTimeout(() => {
      child.kill()
      resolve({ ok: false, exitCode: null, stdout, stderr: `${stderr}\n[timed out after ${timeoutMs} ms]`, truncated })
    }, timeoutMs)

    const onAbort = () => child.kill()
    signal?.addEventListener?.('abort', onAbort, { once: true })

    child.on('error', (error) => {
      clearTimeout(timer)
      signal?.removeEventListener?.('abort', onAbort)
      resolve({ ok: false, exitCode: null, stdout, stderr: `${stderr}\n${String(error)}`, truncated })
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      signal?.removeEventListener?.('abort', onAbort)
      resolve({ ok: code === 0, exitCode: code, stdout, stderr, truncated })
    })
  })
}

/** Bound one result body, spilling the full text to a temp file. */
async function boundText(text, maxChars) {
  if (text.length <= maxChars) return { text, spill: null }
  const dir = mkdtempSync(join(tmpdir(), 'dsh-rea-'))
  const file = join(dir, 'output.txt')
  await writeFile(file, text, 'utf8')
  return {
    text: `${text.slice(0, maxChars)}\n\n[truncated: ${text.length} chars total; full output at ${file}]`,
    spill: file,
  }
}

/** Compact one-line description for a CLI command row. */
function parseCommandRows(llmsText) {
  const rows = []
  for (const line of llmsText.split('\n')) {
    const match = /^\|\s*`rea ([^`]+)`\s*\|\s*(.*?)\s*\|\s*$/.exec(line.trim())
    if (!match) continue
    const signature = match[1].trim()
    const space = signature.indexOf(' ')
    rows.push({
      command: space < 0 ? signature : signature.slice(0, space),
      usage: space < 0 ? `rea ${signature}` : `rea ${signature}`,
      description: match[2].trim(),
    })
  }
  return rows
}

// ---- plugin body -----------------------------------------------------------

/**
 * Register the REA bridge tools.
 * @param ctx - Context providing the tool registry.
 * @param config - resolved plugin configuration.
 */
export function apply(ctx, config) {
  const runtime = makeRuntime(config, ctx.logger)
  const maxChars = config.maxOutputChars
  const defaultTimeoutMs = config.defaultTimeoutMs

  /** Cache for the parsed CLI manifest. */
  let commandCache = null

  async function commands(signal) {
    if (commandCache) return commandCache
    const result = await runCli(runtime, ['--llms'], {
      timeoutMs: Math.min(defaultTimeoutMs, 120_000),
      signal,
      maxChars,
    })
    commandCache = parseCommandRows(result.stdout)
    return commandCache
  }

  // Release the MCP child when this plugin unloads.
  ctx.effect(() => () => {
    try {
      runtime.state.child?.kill()
    } catch {
      /* the child may already be gone */
    }
  }, 'dsh-rea.child')

  ctx.tools.register(defineTool({
    name: 'rea_list',
    description:
      'Discover REA (Reverse Engineer Anything) capabilities before using rea_cli or rea_tool. ' +
      'kind="overview" returns provider readiness plus tool groups; kind="commands" lists the rea CLI commands with usage; ' +
      'kind="tools" lists REA MCP tool names, optionally filtered. Use this instead of guessing a command or tool name.',
    parameters: {
      kind: {
        type: 'string',
        required: true,
        enum: ['overview', 'commands', 'tools'],
        description: 'Which catalog to return.',
      },
      filter: {
        type: 'string',
        description: 'Case-insensitive substring matched against command or tool names and descriptions.',
      },
      limit: {
        type: 'number',
        description: 'Maximum rows for kind="commands" or kind="tools". Defaults to 200.',
      },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    presentCall: (args) => ({ card: 'generic', title: `REA list: ${args.kind}`, kind: 'read', rawInput: args.filter }),
    async execute(args, exec) {
      if (args.kind === 'overview') {
        const lines = [
          `REA bridge: ${runtime.state.ready ? 'ready' : 'CLI not found'}`,
          `cli entry: ${runtime.state.entry || '(unresolved)'}`,
          `node: ${runtime.state.node}`,
        ]
        try {
          const probe = await runCli(runtime, ['doctor', '--json'], {
            timeoutMs: 120_000,
            signal: exec.signal,
            maxChars,
          })
          const payload = probe.stdout.trim().startsWith('{') ? JSON.parse(probe.stdout) : null
          const checks = payload?.checks ?? []
          const healthy = checks.filter((check) => check.ok).map((check) => check.name)
          const broken = checks.filter((check) => !check.ok).map((check) => check.name)
          if (healthy.length) lines.push(`ready checks: ${healthy.join(', ')}`)
          if (broken.length) lines.push(`unavailable checks: ${broken.join(', ')}`)
        } catch (error) {
          lines.push(`doctor failed: ${String(error?.message ?? error)}`)
        }
        lines.push('', 'tool groups (use rea_tool with an exact tool name):')
        for (const [group, tools] of Object.entries(GROUPS)) {
          lines.push(`  ${group}: ${tools.length} tools — ${tools.slice(0, 6).join(', ')}${tools.length > 6 ? ', …' : ''}`)
        }
        lines.push('', 'anything else is reachable as a rea CLI command: rea_list kind="commands"')
        return lines.join('\n')
      }

      if (args.kind === 'commands') {
        const rows = await commands(exec.signal)
        const needle = (args.filter ?? '').toLowerCase()
        const matched = needle
          ? rows.filter(
              (row) =>
                row.command.toLowerCase().includes(needle) || row.description.toLowerCase().includes(needle),
            )
          : rows
        const limit = args.limit ?? 200
        const shown = matched.slice(0, limit)
        const body = shown.map((row) => `${row.usage} — ${row.description}`).join('\n')
        const note =
          matched.length > shown.length
            ? `\n\n[showing ${shown.length} of ${matched.length} commands; narrow with filter]`
            : ''
        return `${shown.length} rea CLI command(s):\n\n${body}${note}`
      }

      const tools = await runtime.toolList(defaultTimeoutMs)
      const needle = (args.filter ?? '').toLowerCase()
      const decorated = tools.map((tool) => ({
        name: tool.name,
        group: TOOL_GROUP.get(tool.name) ?? 'other',
        description: String(tool.description ?? '').replace(/\s+/g, ' ').slice(0, 120),
      }))
      const matched = needle
        ? decorated.filter(
            (tool) =>
              tool.name.toLowerCase().includes(needle) || tool.description.toLowerCase().includes(needle),
          )
        : decorated
      const limit = args.limit ?? 200
      const shown = matched.slice(0, limit)
      const body = shown.map((tool) => `[${tool.group}] ${tool.name} — ${tool.description}`).join('\n')
      const note =
        matched.length > shown.length
          ? `\n\n[showing ${shown.length} of ${matched.length} MCP tools; narrow with filter]`
          : ''
      return `${matched.length} REA MCP tool(s) advertised (${tools.length} total):\n\n${body}${note}`
    },
  }))

  ctx.tools.register(defineTool({
    name: 'rea_cli',
    description:
      'Run one REA command. `command` is the CLI verb (for example "analyze", "inspect-pe-resources", ' +
      '"analyze-javascript-application"), and `args` are its positional and `--flag` arguments as separate strings. ' +
      'Prefer this for whole-artifact surveys and one-shot analyses; use rea_tool for stateful sessions. ' +
      'Discover exact verbs with rea_list kind="commands".',
    parameters: {
      command: {
        type: 'string',
        required: true,
        description: 'REA CLI verb, without the leading "rea".',
      },
      args: {
        type: 'array',
        items: { type: 'string' },
        description: 'Arguments passed verbatim after the verb, each as its own string.',
      },
      timeoutSec: {
        type: 'number',
        description: 'Wall-clock ceiling in seconds. Ghidra-backed analyses need several minutes.',
      },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    presentCall: (args) => ({
      card: 'generic',
      title: `rea ${args.command}`,
      kind: 'other',
      rawInput: Array.isArray(args.args) ? args.args.slice(0, 4).join(' ') : undefined,
    }),
    async execute(args, exec) {
      if (!runtime.state.ready) {
        return 'REA CLI is not resolvable. Point the dsh-rea config key `reaEntry` at rea-agents/scripts/rea.mjs.'
      }
      const timeoutMs = (args.timeoutSec ?? Math.floor(defaultTimeoutMs / 1000)) * 1000
      const argv = [args.command, ...(Array.isArray(args.args) ? args.args : [])]
      const result = await runCli(runtime, argv, { timeoutMs, signal: exec.signal, maxChars })

      const sections = [`$ rea ${argv.join(' ')}`, `exit: ${result.exitCode ?? 'timeout'}`]
      if (result.stdout.trim()) sections.push('', result.stdout.trim())
      if (result.stderr.trim()) sections.push('', '[stderr]', result.stderr.trim())
      if (result.truncated) sections.push('', '[output exceeded the capture budget and was cut]')
      const body = await boundText(sections.join('\n'), maxChars)

      if (!result.ok && !result.stdout.trim()) {
        throw new Error(`rea ${argv.join(' ')} failed (exit ${result.exitCode}): ${result.stderr.trim().slice(0, 800)}`)
      }
      return body.text
    },
  }))

  ctx.tools.register(defineTool({
    name: 'rea_tool',
    description:
      'Call one REA MCP tool by its exact name with JSON arguments, for stateful work: open_binary then ' +
      'procedure_pseudo_code, xrefs, search_strings and the other analysis verbs. ' +
      'Discover names with rea_list kind="tools". Arguments must match that tool\'s own schema; ' +
      'when a call reports a schema error, re-read rea_list for the tool and correct the argument names.',
    parameters: {
      tool: {
        type: 'string',
        required: true,
        description: 'Exact REA MCP tool name, for example "open_binary".',
      },
      args: {
        type: 'json',
        description: 'Arguments object for that tool, matching its input schema.',
      },
      timeoutSec: {
        type: 'number',
        description: 'Wall-clock ceiling in seconds. Decompilation of a large binary can take minutes.',
      },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    presentCall: (args) => ({ card: 'generic', title: `REA ${args.tool}`, kind: 'other' }),
    async execute(args, exec) {
      if (!runtime.state.ready) {
        return 'REA CLI is not resolvable. Point the dsh-rea config key `reaEntry` at rea-agents/scripts/rea.mjs.'
      }
      const timeoutMs = (args.timeoutSec ?? Math.floor(defaultTimeoutMs / 1000)) * 1000
      const tools = await runtime.toolList(timeoutMs)
      const known = tools.find((tool) => tool.name === args.tool)
      if (!known && !TOOL_GROUP.has(args.tool)) {
        const nearby = tools
          .map((tool) => tool.name)
          .filter((tool) => tool.includes(args.tool.slice(0, 4)))
          .slice(0, 12)
        throw new Error(
          `unknown REA tool "${args.tool}"${nearby.length ? `; similar: ${nearby.join(', ')}` : ''}. Use rea_list kind="tools".`,
        )
      }

      await runtime.ensureChild(timeoutMs)
      const response = await runtime.request(
        'tools/call',
        { name: args.tool, arguments: args.args ?? {} },
        timeoutMs,
      )
      if (response.error) {
        throw new Error(`REA tool ${args.tool} failed: ${response.error.message ?? JSON.stringify(response.error)}`)
      }
      const content = response.result?.content ?? []
      const text = content
        .map((block) => (block.type === 'text' ? block.text : `[${block.type} block]`))
        .join('\n')
      const bounded = await boundText(text || '(no textual content)', maxChars)
      return bounded.text
    },
  }))
}

export default { name, inject, Config, apply }
