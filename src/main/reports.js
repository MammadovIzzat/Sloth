'use strict'
/** Exports: the self-contained HTML report, plain text, and the JSON bundle.
 *
 * Ported from views/reports.py and templates/export.html. The Jinja template
 * becomes a function here; the markup, the inlined Nocturne palette and the
 * decision not to embed 4 MB of webfonts are all unchanged, so a report from
 * this build looks the same as one from the Python build.
 */
const fs = require('node:fs')
const path = require('node:path')

const store = require('./store')
const transfer = require('./transfer')
const { SHOTS_DIR } = require('./config')

/** Everything one task knows, ready for rendering or serialising. */
function taskBundle (task) {
  const hosts = store.taskHosts(task.id)
  const scans = {}
  for (const row of store.listNmapScans({ taskId: task.id })) {
    const full = store.getNmapScan(row.id)
    if (!scans[full.ip]) scans[full.ip] = []
    scans[full.ip].push({
      id: full.id,
      tool: full.tool,
      created_at: full.created_at,
      command: full.command,
      raw_output: full.raw_output,
      screenshots: parseJson(full.screenshots_json),
    })
  }
  return { task: { ...task }, hosts, scans }
}

function parseJson (value) {
  try {
    const parsed = JSON.parse(value || '[]')
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

/** Renders one export. Returns {filename, mime, body}. */
function render (format, { title, slug, sections, project = null, version = '?' }) {
  if (format === 'json') {
    const payload = transfer.envelope(title, sections, project, version)
    return {
      filename: `${slug}.json`,
      mime: 'application/json',
      body: JSON.stringify(payload, null, 2),
    }
  }
  if (format === 'txt') {
    return {
      filename: `${slug}.txt`,
      mime: 'text/plain; charset=utf-8',
      body: renderText(title, sections, project),
    }
  }
  // HTML: self-contained, screenshots inlined as data URIs.
  for (const section of sections) {
    for (const list of Object.values(section.scans)) {
      for (const scan of list) {
        for (const shot of scan.screenshots) shot.data_uri = inlinePng(shot.file)
      }
    }
  }
  return {
    filename: `${slug}.html`,
    mime: 'text/html; charset=utf-8',
    body: renderHtml(title, sections, project),
  }
}

function inlinePng (name) {
  if (!name) return null
  try {
    const raw = fs.readFileSync(path.join(SHOTS_DIR, path.basename(name)))
    return 'data:image/png;base64,' + raw.toString('base64')
  } catch {
    return null
  }
}

/** The one-line description of how a task was run, as the pages show it. */
function scanConfig (task) {
  const bits = [task.scan_type || 'full']
  for (const [label, key] of [['', 'engine'], ['discovery ', 'discovery'],
    ['TCP ', 'tcp_ports'], ['UDP ', 'udp_ports'], ['top ', 'top_ports']]) {
    if (task[key]) bits.push(`${label}${task[key]}`)
  }
  if (task.rate) bits.push(`${task.rate} pkts/s`)
  return bits.join(' · ')
}

/** Plain text, carrying what the HTML report carries.
 *
 * The finding lines keep the shape 'ip:port (proto/state)  service' — this is
 * the format people pipe into grep and cut, so it stays stable even as the
 * surrounding report grows.
 */
function renderText (title, sections, project) {
  const out = [`# ${title}`]
  if (project) {
    if (project.client) out.push(`client: ${project.client}`)
    out.push(`project created ${project.created_at}`)
    if (project.description) out.push(project.description)
  }

  const hosts = sections.reduce((n, s) => n + s.hosts.length, 0)
  const ports = sections.reduce((n, s) =>
    n + s.hosts.reduce((m, h) => m + h.ports.length, 0), 0)
  out.push('', `${sections.length} task(s) · ${hosts} host(s) · ${ports} open/filtered port(s)`)

  for (const section of sections) {
    const task = section.task
    out.push('', '='.repeat(72), `## ${task.name}`, '')
    const meta = [['target', task.target], ['status', task.status],
      ['scan', scanConfig(task)], ['started', task.started_at],
      ['finished', task.finished_at], ['notes', task.notes], ['error', task.error]]
    for (const [key, value] of meta) {
      if (value) out.push(`   ${key.padEnd(10)} ${value}`)
    }
    out.push('')

    if (!section.hosts.length) {
      out.push('   (no hosts with open ports were found by this task)')
      continue
    }

    for (const host of section.hosts) {
      if (!host.ports.length) out.push(`${host.ip}  (up — no open ports recorded)`)
      for (const port of host.ports) {
        const service = port.service ? `  ${port.service}` : ''
        out.push(`${host.ip}:${port.port} (${port.proto}/${port.state})${service}`)
      }
      for (const scan of section.scans[host.ip] || []) {
        out.push('', `   nmap · ${scan.tool} · ${scan.created_at}`, `   $ ${scan.command}`)
        for (const shot of scan.screenshots) out.push(`   screenshot: ${shot.url || ''}`)
        out.push('   ' + '-'.repeat(60))
        for (const line of String(scan.raw_output || '').replace(/\s+$/, '').split('\n')) {
          out.push('   ' + line)
        }
        out.push('   ' + '-'.repeat(60), '')
      }
    }
  }
  return out.join('\n') + '\n'
}

/** Escapes text for HTML. Everything interpolated below is attacker-influenced
 *  — service banners, hostnames and nmap output come off the scanned host. */
function esc (value) {
  if (value === null || value === undefined) return ''
  return String(value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

const STYLE = `
    /* Nocturne's palette, inlined. Deliberately self-contained: no stylesheet
       link, no CDN, screenshots embedded as data URIs, so this file still
       renders years from now on a machine with no network.

       The webfonts are the one thing left out — Inter and the icon set are
       4 MB, and attaching that to every exported report to change the shape of
       the letters is a poor trade. System stacks stand in. */
    :root {
      --bg:        oklch(0.212 0.033 255);
      --surface:   oklch(0.276 0.026 255);
      --sunken:    oklch(0.259 0.018 255);
      --neutral:   oklch(0.355 0.024 255);
      --text:      #e9e9ed;
      --accent:    oklch(0.660 0.125 258);
      --accent-300:oklch(0.859 0.055 258);
      --divider:   color-mix(in srgb, #e9e9ed 16%, transparent);
      --muted:     color-mix(in srgb, #e9e9ed 55%, transparent);
      --faint:     color-mix(in srgb, #e9e9ed 40%, transparent);
      --mono:      ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    * { box-sizing: border-box; }
    body { background: var(--bg); color: var(--text); margin: 0; padding: 34px 22px 80px;
           font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
           font-size: 14px; line-height: 1.55; }
    .wrap { max-width: 1080px; margin: 0 auto; }

    h1 { font-size: 24px; letter-spacing: -0.02em; margin: 0 0 6px; }
    h2 { font-size: 17px; margin: 40px 0 4px; }
    h3 { font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase;
         color: var(--accent-300); margin: 22px 0 8px; font-weight: 600; }
    .kicker { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase;
              color: var(--faint); margin: 0 0 6px; }
    .meta  { color: var(--muted); font-size: 12px; margin: 4px 0 0; }
    .head  { padding-bottom: 17px; margin-bottom: 22px; border-bottom: 1px solid var(--divider); }
    .empty { color: var(--faint); font-style: italic; font-size: 12px; }

    .card { background: var(--surface); border: 1px solid var(--divider);
            border-radius: 14px; padding: 17px; margin: 11px 0 17px; }
    .ip   { font-family: var(--mono); font-size: 15px; font-weight: 600; }

    table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 11px; }
    th { text-align: left; font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase;
         color: var(--muted); font-weight: 600; padding: 6px 8px;
         border-bottom: 1px solid var(--divider); }
    td { padding: 6px 8px; border-bottom: 1px solid
         color-mix(in srgb, #e9e9ed 8%, transparent); vertical-align: top; }
    td.port { font-family: var(--mono); color: var(--accent-300); white-space: nowrap; }
    td.src  { font-size: 11px; color: var(--faint); }

    /* One neutral pill, matching the interface: state is text, not alarm colour. */
    .tag { display: inline-block; font-size: 11px; padding: 2px 8px; border-radius: 999px;
           background: var(--neutral); border: 1px solid var(--divider);
           font-family: var(--mono); white-space: nowrap; }
    .tag.dim { opacity: 0.62; }

    pre { white-space: pre-wrap; word-break: break-word; background: var(--sunken);
          border: 1px solid var(--divider); border-radius: 8px; padding: 12px;
          font-family: var(--mono); font-size: 11.5px; line-height: 1.65;
          color: color-mix(in srgb, #e9e9ed 72%, transparent); overflow-x: auto; margin: 0; }
    details { margin: 10px 0 0; }
    summary { cursor: pointer; color: var(--accent-300); font-size: 12px; }

    .shots { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
             gap: 14px; margin-top: 8px; }
    img { max-width: 100%; display: block; border: 1px solid var(--divider);
          border-radius: 8px; }

    /* Reports get printed and pasted into deliverables. */
    @media print {
      body { background: #fff; color: #111; }
      .card, pre { background: #fff; border-color: #ccc; }
      .tag { background: #eee; }
      a { color: inherit; }
    }
`

function renderHtml (title, sections, project) {
  const hostTotal = sections.reduce((n, s) => n + s.hosts.length, 0)
  const portTotal = sections.reduce((n, s) =>
    n + s.hosts.reduce((m, h) => m + h.ports.length, 0), 0)

  const parts = []
  parts.push(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)} — Sloth report</title>
<style>${STYLE}</style>
</head>
<body>
<div class="wrap">
    <div class="head">
        <p class="kicker">Sloth report</p>
        <h1>${esc(title)}</h1>
        <p class="meta">`)
  if (project) {
    if (project.client) parts.push(`client: ${esc(project.client)} · `)
    parts.push(`project created ${esc(project.created_at)}`)
  }
  parts.push('</p>')
  if (project && project.description) {
    parts.push(`\n        <p class="meta">${esc(project.description)}</p>`)
  }
  parts.push(`
        <p class="meta">
            ${sections.length} task(s) · ${hostTotal} host(s) ·
            ${portTotal} open/filtered port(s)
        </p>
    </div>
`)

  for (const section of sections) {
    const task = section.task
    const meta = [
      `${esc(task.scan_type || 'full')}`,
      task.engine ? ` · ${esc(task.engine)}` : '',
      ` · target ${esc(task.target)} · status ${esc(task.status)}`,
      task.discovery ? ` · discovery ${esc(task.discovery)}` : '',
      task.tcp_ports ? ` · TCP ${esc(task.tcp_ports)}` : '',
      task.udp_ports ? ` · UDP ${esc(task.udp_ports)}` : '',
      task.top_ports ? ` · top ${esc(task.top_ports)}` : '',
      task.rate ? ` · ${esc(task.rate)} pkts/s` : '',
      task.started_at ? ` · started ${esc(task.started_at)}` : '',
      task.finished_at ? ` · finished ${esc(task.finished_at)}` : '',
    ].join('')

    parts.push(`    <h2>${esc(task.name)}</h2>\n    <p class="meta">${meta}</p>\n`)
    if (task.notes) parts.push(`    <p class="meta">Notes: ${esc(task.notes)}</p>\n`)
    if (task.error) parts.push(`    <p class="meta">Error: ${esc(task.error)}</p>\n`)

    if (!section.hosts.length) {
      parts.push('    <p class="empty" style="margin-top:11px">No hosts with open ' +
        'ports were found by this task.</p>\n')
    }

    for (const host of section.hosts) {
      parts.push(`    <div class="card">\n        <div class="ip">${esc(host.ip)}</div>\n`)
      if (host.ports.length) {
        parts.push(`        <table>
            <thead><tr>
                <th style="width:110px">Port</th><th style="width:130px">State</th>
                <th>Service</th><th style="width:90px">Source</th>
            </tr></thead>
            <tbody>
`)
        for (const port of host.ports) {
          const dim = String(port.state || '').startsWith('open') ? '' : ' dim'
          parts.push(`            <tr>
                <td class="port">${esc(port.port)}/${esc(port.proto)}</td>
                <td><span class="tag${dim}">${esc(port.state)}</span></td>
                <td>${esc(port.service || '—')}</td>
                <td class="src">${esc(port.source)}</td>
            </tr>
`)
        }
        parts.push('            </tbody>\n        </table>\n')
      } else {
        parts.push('        <p class="empty" style="margin-top:8px">host is up — ' +
          'no open ports recorded</p>\n')
      }

      for (const scan of section.scans[host.ip] || []) {
        parts.push(`        <h3>nmap · ${esc(scan.tool)} · ${esc(scan.created_at)}</h3>\n`)
        if (scan.screenshots.length) {
          parts.push('        <div class="shots">\n')
          for (const shot of scan.screenshots) {
            parts.push(`            <div>
                <p class="meta" style="margin-bottom:5px">${esc(shot.url)}</p>
`)
            parts.push(shot.data_uri
              ? `                <img src="${shot.data_uri}" alt="screenshot of ${esc(shot.url)}">\n`
              : '                <p class="empty">Screenshot file missing.</p>\n')
            parts.push('            </div>\n')
          }
          parts.push('        </div>\n')
        }
        parts.push(`        <details>
            <summary>Command &amp; full nmap output</summary>
            <pre>${esc(scan.command)}

${esc(scan.raw_output)}</pre>
        </details>
`)
      }
      parts.push('    </div>\n')
    }
  }

  parts.push('</div>\n</body>\n</html>\n')
  return parts.join('')
}

// --- the two entry points -------------------------------------------------

function exportTask (taskId, format, version) {
  const task = store.getTask(taskId)
  if (!task) throw new Error('Task not found.')
  return render(format, {
    title: `${task.project_name} · ${task.name}`,
    slug: `task-${taskId}`,
    sections: [taskBundle(task)],
    version,
  })
}

function exportProject (projectId, format, version) {
  const project = store.getProject(projectId)
  if (!project) throw new Error('Project not found.')
  return render(format, {
    title: project.name,
    slug: `project-${projectId}`,
    sections: store.listTasks(projectId).map(taskBundle),
    project,
    version,
  })
}

module.exports = { taskBundle, render, exportTask, exportProject, renderText, renderHtml }
