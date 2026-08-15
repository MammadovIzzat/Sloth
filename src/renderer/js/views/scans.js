'use strict'
/** Saved nmap reports: the list, and one report in full. */
import { api } from '../api.js'
import { el, icon, button, input } from '../dom.js'

export async function renderScans (context) {
  let projectId = ''
  let search = ''

  const summary = el('p.sub')
  const list = el('div.stack')

  const box = input({
    id: 'scan-search',
    type: 'search',
    placeholder: 'Search by address, tool, task or project…',
    autocomplete: 'off',
  })
  const projectPicker = el('select.input.scan-filter-project')

  /** Re-queries and repaints. Filtering happens in SQL, so this searches every
   *  saved report rather than only the ones already on screen. */
  async function refresh () {
    let data
    try {
      data = await api.scans.list({ projectId: projectId || null, search, limit: 200 })
    } catch (err) {
      context.flash(err.message, 'error')
      return
    }

    // Rebuild the project list only when it changes, so reselecting does not
    // fight the user's cursor.
    const wanted = ['', ...data.projects.map((p) => p.id)].join('|')
    if (projectPicker.dataset.keys !== wanted) {
      projectPicker.dataset.keys = wanted
      projectPicker.replaceChildren(
        el('option', { value: '', text: 'All projects' }),
        ...data.projects.map((p) => el('option', { value: p.id, text: p.name })))
      projectPicker.value = projectId
    }

    const filtered = search || projectId
    summary.textContent = data.truncated
      ? `Showing the newest 200 of ${data.total} match(es).`
      : filtered
        ? `${data.total} of ${data.grandTotal} report(s) match.`
        : `${data.total} report(s).`

    if (!data.scans.length) {
      list.replaceChildren(el('div.card.elev-sm.card-empty',
        el('p.sub', {
          text: data.grandTotal
            ? 'Nothing matches that. Try a different address, tool or project.'
            : 'No nmap reports yet — rescan a host from its task page.',
        })))
      return
    }

    list.replaceChildren(...data.scans.map((scan) =>
      el('a.card.elev-sm.scan-row', { href: `#scan/${scan.id}` },
        icon('file-text'),
        el('span.mono', { text: scan.ip }),
        el('span.card-meta', {
          text: [scan.created_at, scan.tool, scan.project_name, scan.task_name]
            .filter(Boolean).join(' · '),
        }))))
  }

  // Typing re-queries, but not on every keystroke: a short pause keeps a long
  // scan history from being searched once per letter.
  let timer = null
  box.addEventListener('input', () => {
    search = box.value
    clearTimeout(timer)
    timer = setTimeout(refresh, 180)
  })
  projectPicker.addEventListener('change', () => {
    projectId = projectPicker.value
    refresh()
  })

  const wrap = el('div.wrap',
    el('div.page-head',
      el('div',
        el('h3', { text: 'Saved nmap scans' }),
        summary)),
    el('div.scan-filters', box, projectPicker),
    list)

  await refresh()
  return wrap
}

export async function renderScanResult (context, scanId) {
  const { scan, ports, shots } = await api.scans.get(scanId)

  return el('div.wrap',
    el('div.page-head',
      el('div',
        el('p.card-kicker', {
          text: [scan.project_name, scan.task_name].filter(Boolean).join(' · '),
        }),
        el('h3', { text: `${scan.ip} — ${scan.tool}` }),
        el('p.sub', { text: scan.created_at }))),

    ports.length
      ? el('div.card.elev-sm.table-card.section',
        el('table.table',
          el('thead', el('tr',
            el('th.col-port', { text: 'Port' }),
            el('th.col-port', { text: 'State' }),
            el('th', { text: 'Service' }))),
          el('tbody', ports.map((port) => el('tr',
            el('td', el('span.port', el('span.port-num', { text: `${port.port}/${port.proto}` }))),
            el('td', el('span.tag.tag-neutral', { text: port.state || '' })),
            el('td', { text: port.service || '—' }))))))
      : null,

    shots.length
      ? el('div.section',
        el('h6.card-kicker.section-head', { text: 'Screenshots' }),
        el('div.shots',
          shots.map((shot) => el('div.card.elev-sm.shot-card',
            el('p.card-meta',
              el('a', {
                href: '#',
                text: shot.url,
                onclick: (event) => {
                  event.preventDefault()
                  api.openExternal(shot.url).catch((err) => context.flash(err.message, 'error'))
                },
              })),
            shot.data_uri
              ? el('img.shot-img', { src: shot.data_uri, alt: `screenshot of ${shot.url}` })
              : el('p.sub', { text: 'Screenshot file missing.' })))))
      : null,

    el('h6.card-kicker.section-head', { text: 'Command and full output' }),
    el('div.card.elev-sm.log-card',
      el('pre.log', { text: (scan.command || '') + '\n\n' + (scan.raw_output || '') })))
}
