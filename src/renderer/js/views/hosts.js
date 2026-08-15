'use strict'
/** The host results view, shared by the task page and the project page.
 *
 * Both show the same thing — hosts and their open ports — so both get the same
 * Table/Cards toggle and the same pill markup. The preference is one setting,
 * not one per page: someone who prefers cards prefers them everywhere.
 *
 * The only difference is what sits in a card's header. A task can rescan a
 * host, because a rescan belongs to a task; the project view has no single
 * task to attribute one to, so it links to where the host was found instead.
 */
import { el, icon } from '../dom.js'

const VIEW_KEY = 'sloth.hostview'

/** The remembered choice, defaulting to the table. */
export function savedView () {
  try {
    const stored = window.localStorage.getItem(VIEW_KEY)
    if (stored === 'table' || stored === 'cards') return stored
  } catch { /* private mode; fall through */ }
  return 'table'
}

function remember (view) {
  try {
    window.localStorage.setItem(VIEW_KEY, view)
  } catch { /* the choice just will not persist */ }
}

/** The segmented Table/Cards control. `apply` receives the chosen view. */
export function viewToggle (apply) {
  const seg = el('div.seg')
  for (const [value, iconName, label] of [['table', 'rows', 'Table'],
    ['cards', 'squares-four', 'Cards']]) {
    const radio = el('input', { type: 'radio', name: 'hostview', value })
    radio.addEventListener('change', () => {
      if (!radio.checked) return
      remember(value)
      apply(value)
    })
    seg.append(el('label.seg-opt', radio, icon(iconName), label))
  }
  return seg
}

/** Ties a toggle to its two panes: shows one, hides the other, marks the radio. */
export function bindView (root, { table, cards, seg }, view) {
  root.dataset.view = view
  table.hidden = view !== 'table'
  cards.hidden = view !== 'cards'
  const radio = seg.querySelector(`input[value="${view}"]`)
  if (radio) radio.checked = true
}

/** One port, as the design draws it: a neutral tag, the number in the accent
 *  colour, the service quieter beside it. `.port` is a modifier on `.tag` —
 *  on its own it has no pill at all. */
export function portPill (port, extra = '') {
  const open = String(port.state || '').startsWith('open')
  return el('span', {
    class: `tag tag-neutral port${open ? '' : ' port-filtered'}`,
    title: [port.state, extra || (port.source ? `found by ${port.source}` : null)]
      .filter(Boolean).join(' · '),
    dataset: { port: `${port.port}/${port.proto}` },
  },
  el('span.port-num', { text: `${port.port}/${port.proto}` }),
  port.service ? el('span.port-svc', { text: port.service }) : null)
}

/** The table body: one row per port, plus a row for a host with none. */
export function fillTable (body, hosts, lastColumn) {
  for (const host of hosts) {
    if (!host.ports.length) {
      body.append(el('tr',
        el('td.mono', { text: host.ip }),
        el('td.cell-muted', { colspan: 3, text: 'up — no open ports' })))
      continue
    }
    for (const port of host.ports) {
      body.append(el('tr',
        el('td.mono', { text: host.ip }),
        el('td', el('span.port', el('span.port-num', { text: `${port.port}/${port.proto}` }))),
        el('td', { text: port.service || '—' }),
        el('td.cell-muted', { text: lastColumn(port, host) })))
    }
  }
}

/** A host card. `header` supplies whatever goes opposite the address. */
export function hostCard (host, header, pillNote) {
  return el('div.card.elev-sm.host-card',
    el('div.host-card-head',
      el('div',
        el('span.mono.host-ip', { text: host.ip }),
        host.hostname ? el('span.card-meta', { text: ' ' + host.hostname }) : null),
      header || null),
    el('div.ports',
      host.ports.length
        ? host.ports.map((port) => portPill(port, pillNote ? pillNote(port, host) : ''))
        : el('span.host-empty', { text: 'host is up — no open ports recorded' })))
}

/** The header row above the results: title, count, toggle, and whatever else
 *  the page wants on the right (the task page puts its export links there). */
export function resultsHeader (title, countNode, seg, extra) {
  return el('div.row-between.results-head',
    el('div.results-title',
      el('h6.card-kicker.flush', { text: title }),
      countNode),
    el('div.results-tools', seg, extra || null))
}

/** The table shell, so both pages get identical columns. */
export function hostTable (lastHeading, body) {
  return el('div.card.elev-sm.table-card', { id: 'resultsTable' },
    el('table.table',
      el('thead', el('tr',
        el('th.col-host', { text: 'Host' }),
        el('th.col-port', { text: 'Port' }),
        el('th', { text: 'Service' }),
        el('th.col-src', { text: lastHeading }))),
      body))
}
