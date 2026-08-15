'use strict'
/** One task: controls, the live scanner log, and results as they arrive.
 *
 * The Flask build streamed this over server-sent events. Here the same events
 * arrive on the IPC bridge, so the shape of the payloads is unchanged — only
 * the transport differs.
 */
import { api } from '../api.js'
import {
  el, clear, replace, icon, button, field, input, select, statusTag, shortDate,
} from '../dom.js'
import {
  bindView, fillTable, hostCard, hostTable, resultsHeader, savedView, viewToggle,
} from './hosts.js'

export async function renderTask (context, taskId) {
  const data = await api.tasks.get(taskId)
  const { task } = data

  let hosts = data.hosts
  let scans = data.scans || []
  // Supplied by the engine, so the menu and the code that runs it stay in step.
  const rescanTools = data.rescanTools || []
  const rescans = new Map(Object.entries(data.rescans || {}))

  /** The newest saved nmap report for a host, if it has one. */
  const reportFor = (address) => scans.find((scan) => scan.ip === address) || null

  const shotCount = (scan) => {
    try {
      const parsed = JSON.parse(scan.screenshots_json || '[]')
      return Array.isArray(parsed) ? parsed.length : 0
    } catch {
      return 0
    }
  }

  // --- header -----------------------------------------------------------
  const statusSlot = el('span', statusTag(task.status))
  const progressBar = el('div.bar-fill')
  const progressText = el('span.card-meta', { text: '' })
  const controls = el('div.page-actions')

  const setProgress = (percent) => {
    progressBar.style.width = `${Math.max(0, Math.min(100, percent))}%`
  }
  setProgress(task.progress || 0)

  // --- log --------------------------------------------------------------
  const logBox = el('pre.log', { text: data.log || '' })
  const appendLog = (line) => {
    const atBottom = logBox.scrollTop + logBox.clientHeight >= logBox.scrollHeight - 30
    logBox.append(document.createTextNode(line + '\n'))
    if (atBottom) logBox.scrollTop = logBox.scrollHeight
  }

  // --- results ----------------------------------------------------------
  // Both views are built; the toggle shows one. Keeping them both in the DOM
  // is what lets findings stream into whichever is hidden without a re-render.
  const hostCount = el('span.host-meta')
  const tableBody = el('tbody')
  const cardsBox = el('div.stack', { id: 'resultsCards' })

  // Which rescan tool each host's picker is set to. Rebuilding a card creates a
  // fresh <select>, and without this every redraw would silently reset a
  // deliberate choice back to nmap.
  const toolChoice = new Map()

  const drawResults = () => {
    const ports = hosts.reduce((n, h) => n + h.ports.length, 0)
    hostCount.textContent = `${hosts.length} host(s), ${ports} port(s)`

    // replaceChildren, not clear-then-append: emptying a container collapses
    // the document, the browser clamps the window scroll to the top, and
    // refilling cannot put it back. Swapping in one operation never leaves a
    // zero-height page, so a rescan no longer throws you to the top of a long
    // host list.
    const rows = el('tbody')
    fillTable(rows, hosts, (port) => port.source || '')
    tableBody.replaceChildren(...rows.childNodes)

    const cards = hosts.map((host) => hostCard(host, rescanControls(host)))
    if (!cards.length) {
      cards.push(el('div.card.elev-sm.card-empty',
        el('p.sub', { text: 'Nothing found yet.' })))
    }
    cardsBox.replaceChildren(...cards)
  }

  /** What sits opposite the address on a task's host card: a rescan picker, or
   *  a stop button while one is running. */
  function rescanControls (host) {
    const busy = rescans.get(host.ip)
    if (busy) {
      return el('div.host-actions',
        el('span.tag.tag-run', { text: `${busy} running` }),
        button('Stop', {
          kind: 'btn-ghost',
          iconName: 'x',
          onclick: async () => {
            try {
              await api.scan.stopHost(taskId, host.ip)
            } catch (err) {
              context.flash(err.message, 'error')
            }
          },
        }))
    }

    const actions = el('div.host-actions')

    // A host that has been rescanned keeps its report one click away. Without
    // this the enriched service names appear with no way to reach the output
    // and screenshots they came from.
    const report = reportFor(host.ip)
    if (report) {
      const shots = shotCount(report)
      actions.append(el('a.btn.btn-ghost.nmap-report-btn', {
        href: `#scan/${report.id}`,
        title: `${report.tool} · ${report.created_at}`,
      }, icon('file-text'), shots ? `Report (${shots})` : 'Report'))
    }

    const usable = rescanTools.filter((entry) => entry.available)
    const chosen = toolChoice.get(host.ip) || (usable[0] && usable[0].key) || ''
    const picker = el('select.input.host-tool')
    for (const entry of rescanTools) {
      picker.append(el('option', {
        value: entry.key,
        // A missing scanner stays listed but unpickable, so it is obvious that
        // the option exists and what would enable it.
        disabled: entry.available ? null : 'disabled',
        title: entry.available ? entry.note : `${entry.tool} is not installed`,
        text: entry.available ? entry.label : `${entry.label} — ${entry.tool} not installed`,
        selected: entry.key === chosen ? 'selected' : null,
      }))
    }
    if (chosen) picker.value = chosen
    picker.addEventListener('change', () => toolChoice.set(host.ip, picker.value))

    actions.append(picker, button('Rescan', {
      kind: 'btn-secondary',
      iconName: 'crosshair',
      onclick: async () => {
        try {
          await api.scan.rescanHost(taskId, host.ip, picker.value, task.project_id)
        } catch (err) {
          context.flash(err.message, 'error')
        }
      },
    }))
    return actions
  }

  // --- scan settings ------------------------------------------------------
  // A task is a target, not one fixed scan. Change these, press Start, and the
  // new run's findings accumulate against the same task rather than replacing
  // what is already there — which is how "nmap top ports now, full masscan
  // sweep afterwards" stays a single task.
  const settings = scanSettings(task, data)

  // --- the reports list beside the log ------------------------------------
  const nmapList = el('div.nmap-list', { id: 'nmapList' })
  const nmapCard = el('div.card.elev-sm.nmap-card',
    el('h6.card-kicker.flush.nmap-head', { text: 'Nmap reports' }), nmapList)

  const drawReports = () => {
    nmapCard.hidden = !scans.length
    nmapList.replaceChildren(...scans.map((scan) => {
      const shots = shotCount(scan)
      return el('a.ellipsis.nmap-entry', {
        href: `#scan/${scan.id}`,
        title: `${scan.tool} · ${scan.created_at}`,
      }, `${scan.ip} · ${shortDate(scan.created_at)}${shots ? ` · ${shots} shot(s)` : ''}`)
    }))
  }
  drawReports()

  drawResults()

  // --- table / cards toggle ---------------------------------------------
  const tableView = hostTable('Source', tableBody)
  const results = el('div', { id: 'results' }, tableView, cardsBox)
  const seg = viewToggle((view) =>
    bindView(results, { table: tableView, cards: cardsBox, seg }, view))

  // --- controls ---------------------------------------------------------
  const rebuildControls = (status, paused) => {
    clear(controls)
    const running = status === 'running' || status === 'paused'
    if (!running) {
      controls.append(button('Scan settings', {
        kind: 'btn-ghost',
        iconName: 'gear',
        onclick: () => settings.toggle(),
      }))
      controls.append(button('Start scan', {
        kind: 'btn-primary',
        iconName: 'play',
        // Always send what the panel shows, open or not: what you can see is
        // what runs, and the settings are the task's own current values until
        // you change them.
        onclick: () => guard(async () => {
          // Flip to the running controls at once: waiting for the first event
          // leaves Start sitting there while the scan is already going.
          rebuildControls('running', false)
          replace(statusSlot, statusTag('running'))
          try {
            await api.scan.start(taskId, settings.values())
          } catch (err) {
            // It never started, so put the controls back as they were.
            rebuildControls(task.status, false)
            replace(statusSlot, statusTag(task.status))
            throw err
          }
        }),
      }))
      if (task.resumable) {
        controls.append(button('Resume saved', {
          kind: 'btn-secondary',
          iconName: 'clock-counter-clockwise',
          onclick: () => guard(() => api.scan.resumeSaved(taskId)),
        }))
      }
    } else {
      controls.append(paused
        ? button('Resume', { kind: 'btn-secondary', iconName: 'play', onclick: () => guard(() => api.scan.resume(taskId)) })
        : button('Pause', { kind: 'btn-secondary', iconName: 'pause', onclick: () => guard(() => api.scan.pause(taskId)) }))
      controls.append(button('Stop', {
        kind: 'btn-danger', iconName: 'stop', onclick: () => guard(() => api.scan.stop(taskId)),
      }))
    }
    controls.append(button('Delete', {
      kind: 'btn-ghost',
      iconName: 'trash',
      onclick: () => {
        const { close } = context.dialog('Delete this task?', [
          el('p.sub', { text: 'Its findings, log and screenshots are removed with it.' }),
        ], (closeIt) => [button('Delete', {
          kind: 'btn-danger',
          onclick: async () => {
            const { projectId } = await api.tasks.remove(taskId)
            closeIt()
            context.flash('Task deleted.')
            context.go(`projects/${projectId}`)
          },
        })])
        void close
      },
    }))
  }

  const guard = async (fn) => {
    try { await fn() } catch (err) { context.flash(err.message, 'error') }
  }
  rebuildControls(task.status, data.paused)

  // --- live events ------------------------------------------------------
  const unsubscribe = api.onScanEvent(async (event) => {
    if (event.task_id !== taskId) return
    switch (event.type) {
      case 'log':
        appendLog(event.line)
        break
      case 'progress':
        setProgress(event.percent)
        progressText.textContent =
          `${event.percent.toFixed(1)}%` +
          (event.rateKpps ? ` · ${event.rateKpps} kpps` : '') +
          (event.remaining ? ` · ${event.remaining} left` : '')
        break
      case 'phase':
        replace(statusSlot, statusTag('running'))
        rebuildControls('running', false)
        progressText.textContent = `${event.phase}${event.tool ? ' · ' + event.tool : ''}`
        break
      case 'status':
        replace(statusSlot, statusTag(event.status))
        rebuildControls(event.status, event.status === 'paused')
        break
      case 'discovered':
      case 'host':
        hosts = await api.tasks.get(taskId).then((fresh) => fresh.hosts)
        drawResults()
        break
      case 'rescan': {
        if (event.state === 'running') rescans.set(event.ip, event.tool)
        else rescans.delete(event.ip)
        if (event.state === 'error') context.flash(`Rescan of ${event.ip}: ${event.error}`, 'error')
        const fresh = await api.tasks.get(taskId)
        hosts = fresh.hosts
        // The report list and the per-host Report button both come from this.
        scans = fresh.scans || []
        drawResults()
        drawReports()
        break
      }
      case 'network':
        context.flash(event.message, event.connected ? 'ok' : 'error')
        break
      case 'done': {
        replace(statusSlot, statusTag(event.status))
        rebuildControls(event.status, false)
        setProgress(100)
        const fresh = await api.tasks.get(taskId)
        hosts = fresh.hosts
        scans = fresh.scans || []
        task.resumable = fresh.task.resumable
        drawResults()
        drawReports()
        break
      }
    }
  })

  // The router replaces the view wholesale; drop the listener with it so a
  // long session does not accumulate one per visit.
  const wrap = el('div.wrap')
  new MutationObserver((_records, observer) => {
    if (!wrap.isConnected) { unsubscribe(); observer.disconnect() }
  }).observe(document.getElementById('view'), { childList: true })

  const meta = [task.scan_type || 'full', task.engine, task.target,
    task.discovery ? `discovery ${task.discovery}` : null,
    task.tcp_ports ? `TCP ${task.tcp_ports}` : null,
    task.udp_ports ? `UDP ${task.udp_ports}` : null,
    task.top_ports ? `top ${task.top_ports}` : null,
    task.rate ? `${task.rate} pkts/s` : null].filter(Boolean).join(' · ')

  wrap.append(
    el('div.page-head',
      el('div',
        el('p.card-kicker',
          el('a', { href: `#projects/${task.project_id}`, text: task.project_name })),
        el('h3', { text: task.name }, ' ', statusSlot),
        el('p.sub', { text: meta }),
        task.error ? el('p.card-meta.error-text', { text: task.error }) : null),
      controls),

    el('div.bar', progressBar),
    el('div.row-between.progress-row', progressText,
      el('span.card-meta', { text: task.finished_at ? `finished ${task.finished_at}` : '' })),

    settings.node,

    el('div.split',
      el('div.split-main',
        resultsHeader('Hosts and open ports', hostCount, seg,
          exportLinks(context, taskId)),
        results),
      el('div.split-aside',
        el('h6.card-kicker', { text: 'Scanner output' }),
        el('div.card.elev-sm.log-card', logBox),
        nmapCard)))

  bindView(results, { table: tableView, cards: cardsBox, seg }, savedView())

  logBox.scrollTop = logBox.scrollHeight
  return wrap
}

/** The re-run panel: scan type, engine, discovery and ports for the next run.
 *
 * Returns {node, toggle, values}. Fields appear and disappear with the scan
 * type and engine, because showing a masscan rate box next to an nmap quick
 * scan invites someone to set a value that will be ignored.
 */
function scanSettings (task, data) {
  const { scanTypes, engines, discoveryProfiles } = data

  const type = select({ id: 'cfg-type' },
    Object.entries(scanTypes).map(([value, label]) =>
      ({ value, label, selected: value === (task.scan_type || 'full') })))
  const engine = select({ id: 'cfg-engine' },
    Object.entries(engines).map(([value, meta]) =>
      ({ value, label: meta.label, selected: value === task.engine })))
  const discovery = select({ id: 'cfg-discovery' }, [
    { value: '', label: 'None — scan every address', selected: !task.discovery },
    ...discoveryProfiles.map((profile) => ({
      value: profile.key, label: profile.label, selected: profile.key === task.discovery,
    })),
  ])

  const tcp = input({ id: 'cfg-tcp', value: task.tcp_ports || '1-65535' })
  const udp = input({ id: 'cfg-udp', value: task.udp_ports || '', placeholder: 'blank = skip' })
  const top = input({ id: 'cfg-top', type: 'number', min: '1', max: '65535',
    value: String(task.top_ports || 1000) })
  const nmapPorts = input({ id: 'cfg-nmap-ports', placeholder: 'e.g. 1-65535' })
  const rate = input({ id: 'cfg-rate', type: 'number', min: '100',
    value: String(task.rate || 1000) })
  const retries = input({ id: 'cfg-retries', type: 'number', min: '0', max: '10',
    value: String(task.retries ?? 3) })

  const engineHelp = el('p.hint')
  const discoveryHelp = el('p.hint')

  const engineRow = el('div.field', el('label', { for: 'cfg-engine', text: 'Engine' }),
    engine, engineHelp)
  const portRow = el('div.grid-2.cfg-row',
    field('TCP ports', tcp), field('UDP ports', udp))
  const quickRow = el('div',
    el('div.grid-2.cfg-row',
      field('Top ports', top),
    el('div.cfg-row',
      field('Or an explicit range', nmapPorts,
        'An explicit range wins over top-ports — this is how you get an accurate nmap -p-.')))
  const masscanRow = el('div.grid-2.cfg-row',
    field('Rate (pkts/s)', rate), field('Retries', retries))

  /** Shows only the fields the chosen scan type and engine actually use. */
  const sync = () => {
    const isFull = type.value === 'full'
    const isQuick = type.value === 'quick'
    engineRow.hidden = !isFull
    portRow.hidden = !isFull
    quickRow.hidden = !isQuick
    // Rate and retries are masscan's; the other engines pace themselves.
    masscanRow.hidden = !(isFull && engine.value === 'masscan')
    engineHelp.textContent = engines[engine.value]?.note || ''
    const profile = discoveryProfiles.find((p) => p.key === discovery.value)
    discoveryHelp.textContent = profile
      ? profile.description + (profile.local_only ? ' Only works on your own segment.' : '')
      : 'Every address in the range is port-scanned, whether it answers or not.'
  }
  type.addEventListener('change', sync)
  engine.addEventListener('change', sync)
  discovery.addEventListener('change', sync)
  sync()

  const node = el('form.card.elev-sm.cfg-panel.hidden', { id: 'runSettings' },
    el('div.grid-2',
      el('div.field', el('label', { for: 'cfg-type', text: 'Scan type' }), type),
      engineRow),
    el('div.field.cfg-row',
      el('label', { for: 'cfg-discovery', text: 'Host discovery' }), discovery, discoveryHelp),
    portRow, quickRow, masscanRow,
    el('p.hint.cfg-row', {
      text: 'Findings from every run accumulate against this task — nothing is replaced.',
    }))
  node.addEventListener('submit', (event) => event.preventDefault())

  return {
    node,
    toggle: () => { node.classList.toggle('hidden') },
    isOpen: () => !node.classList.contains('hidden'),
    /** Exactly the shape parseScanConfig expects on the main side. */
    values: () => ({
      scan_type: type.value,
      engine: engine.value,
      discovery: discovery.value,
      tcp_ports: tcp.value,
      udp_ports: udp.value,
      top_ports: top.value,
      nmap_ports: nmapPorts.value,
      rate: rate.value,
      retries: retries.value,
    }),
  }
}

/** Export straight from the task page, as the Flask build's HTML/TXT/JSON
 *  links did — here they open the native save dialog. */
function exportLinks (context, taskId) {
  const row = el('div.export-links', el('span.host-meta', { text: 'Export' }))
  for (const format of ['html', 'txt', 'json']) {
    row.append(el('a', {
      href: '#',
      text: format.toUpperCase(),
      onclick: async (event) => {
        event.preventDefault()
        try {
          const result = await api.report.exportOne('task', taskId, format)
          if (result.saved) context.flash(`Exported to ${result.path}`)
        } catch (err) {
          context.flash(err.message, 'error')
        }
      },
    }))
  }
  return row
}
