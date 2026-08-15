'use strict'
/** One project: its tasks, every host it has found, and its saved nmap scans. */
import { api } from '../api.js'
import { el, icon, button, field, input, select, statusTag, shortDate } from '../dom.js'
import { importInto } from './projects.js'
import {
  bindView, fillTable, hostCard, hostTable, resultsHeader, savedView, viewToggle,
} from './hosts.js'

export async function renderProject (context, projectId) {
  const data = await api.projects.get(projectId)
  const { project, tasks, hosts, scans, defaults } = data

  const wrap = el('div.wrap',
    el('div.page-head',
      el('div',
        el('h3', { text: project.name }),
        el('p.sub', {
          text: (project.client ? project.client + ' · ' : '') +
                `created ${project.created_at}`,
        }),
        project.description ? el('p.sub.clamp.spaced', { text: project.description }) : null),
      el('div.page-actions',
        button('Export', {
          kind: 'btn-ghost',
          iconName: 'download-simple',
          onclick: () => exportDialog(context, 'project', projectId, project.name),
        }),
        button('Import', {
          kind: 'btn-ghost',
          iconName: 'upload-simple',
          onclick: () => importInto(context, projectId, null),
        }),
        button('Settings', {
          kind: 'btn-ghost',
          iconName: 'gear',
          onclick: () => settingsDialog(context, project),
        }),
        button('New scan task', {
          kind: 'btn-primary',
          iconName: 'plus',
          onclick: () => newTaskDialog(context, data),
        }))),

    el('h6.card-kicker.section-head', { text: 'Scan tasks' }),
    el('div.stack.section',
      tasks.length
        ? tasks.map((task) => taskRow(task))
        : el('div.card.elev-sm.card-empty',
          el('p.sub', { text: 'No tasks yet. Add one to start scanning.' }))),

    hostResults(hosts),

    el('h6.card-kicker.section-head', { text: 'Nmap reports' }),
    el('div.stack',
      scans.length
        ? scans.map((scan) => el('a.card.elev-sm.scan-row', { href: `#scan/${scan.id}` },
          icon('file-text'),
          el('span.mono', { text: scan.ip }),
          el('span.card-meta', {
            text: `${scan.created_at} · ${scan.tool}${scan.task_name ? ' · ' + scan.task_name : ''}`,
          })))
        : el('div.card.elev-sm.card-empty',
          el('p.sub', { text: 'No nmap reports yet — rescan a host from its task page.' }))))

  return wrap
}

function taskRow (task) {
  const engineLabel = task.scan_type === 'full'
    ? task.engine
    : ({ quick: 'nmap quick', discovery: 'discovery' }[task.scan_type] || task.scan_type)
  const meta = [engineLabel, task.target,
    task.discovery ? `🔎 ${task.discovery}` : null,
    task.tcp_ports ? `TCP ${task.tcp_ports}` : null,
    task.udp_ports ? `UDP ${task.udp_ports}` : null,
    task.top_ports ? `top ${task.top_ports}` : null].filter(Boolean).join(' · ')

  return el('a', {
    href: `#tasks/${task.id}`,
    class: `card elev-sm row-card compact${task.status === 'running' ? ' card-scanning' : ''}`,
  },
  el('div.row-card-main',
    el('div.row-card-title',
      el('span.card-title.small', { text: task.name }),
      statusTag(task.status)),
    el('p.card-meta.spaced-sm', { text: meta }),
    task.error ? el('p.card-meta.error-text', { text: task.error }) : null),
  el('div.row-card-counts',
    el('div', el('b', { text: String(task.host_count) }), ' hosts'),
    el('div', el('b', { text: String(task.finding_count) }), ' ports')))
}

/** Every host in the project, as a table or as cards.
 *
 * Same control and same preference as the task page — a host looks the same
 * wherever you meet it. The last column names the tasks that saw the port
 * rather than the scanner, because at project scope "which run found this"
 * is the question worth answering.
 */
function hostResults (hosts) {
  const seenBy = (port) => (port.tasks || [port.source]).filter(Boolean).join(', ')

  if (!hosts.length) {
    return el('div.section',
      el('h6.card-kicker.section-head', { text: 'All hosts in this project' }),
      el('div.card.elev-sm.card-empty', el('p.sub', { text: 'No hosts found yet.' })))
  }

  const body = el('tbody')
  fillTable(body, hosts, seenBy)
  const table = hostTable('Seen by', body)

  const cards = el('div.stack', { id: 'resultsCards' },
    hosts.map((host) => hostCard(host, null, seenBy)))

  const count = el('span.host-meta', {
    text: `${hosts.length} host(s), ` +
          `${hosts.reduce((n, h) => n + h.ports.length, 0)} port(s)`,
  })
  const seg = viewToggle((view) => bindView(results, { table, cards, seg }, view))
  const results = el('div', { id: 'results' }, table, cards)

  const section = el('div.section',
    resultsHeader('All hosts in this project', count, seg),
    results)
  bindView(results, { table, cards, seg }, savedView())
  return section
}

// --- dialogs --------------------------------------------------------------

function exportDialog (context, kind, id, name) {
  const formats = [
    ['html', 'file-html', 'Report',
      'Self-contained page with the screenshots embedded. For reading and for pasting into a deliverable.'],
    ['json', 'arrows-left-right', 'Transferable data',
      'Everything, screenshots included. This is the file another Sloth can import.'],
    ['txt', 'text-align-left', 'Plain text',
      'One finding per line, in the shape grep and cut expect.'],
  ]
  const { close } = context.dialog(`Export ${name}`,
    formats.map(([format, iconName, label, note]) =>
      el('a.card.elev-sm.export-option', {
        href: '#',
        onclick: async (event) => {
          event.preventDefault()
          try {
            const result = await api.report.exportOne(kind, id, format)
            close()
            if (result.saved) context.flash(`Exported to ${result.path}`)
          } catch (err) {
            context.flash(err.message, 'error')
          }
        },
      }, icon(iconName),
      el('span.export-text',
        el('span.card-title.small', { text: label }),
        el('span.tag.tag-neutral.export-ext', { text: '.' + format }),
        el('p.sub.spaced-sm', { text: note })))),
    () => [])
}

function settingsDialog (context, project) {
  const name = input({ id: 'sp-name', value: project.name })
  const client = input({ id: 'sp-client', value: project.client || '' })
  const description = el('textarea.input', { id: 'sp-desc', rows: 3 })
  description.value = project.description || ''
  const status = select({ id: 'sp-status' }, [
    { value: 'active', label: 'Active', selected: project.status === 'active' },
    { value: 'archived', label: 'Archived', selected: project.status === 'archived' },
  ])

  const { close } = context.dialog('Project settings', [
    field('Name', name), field('Client / scope', client),
    field('Description', description), field('Status', status),
  ], () => [
    button('Delete project', {
      kind: 'btn-danger',
      onclick: async () => {
        const sure = context.dialog('Delete this project?', [
          el('p.sub', {
            text: `“${project.name}” and every task, finding and screenshot in ` +
                  'it will be removed. This cannot be undone.',
          }),
        ], (closeSure) => [button('Delete', {
          kind: 'btn-danger',
          onclick: async () => {
            await api.projects.remove(project.id)
            closeSure(); close()
            context.flash('Project deleted.')
            await context.refreshSidebar()
            context.go('')
          },
        })])
        void sure
      },
    }),
    button('Save', {
      kind: 'btn-primary',
      onclick: async () => {
        try {
          await api.projects.update(project.id, {
            name: name.value, client: client.value,
            description: description.value, status: status.value,
          })
          close()
          await context.refreshSidebar()
          context.go(`projects/${project.id}`)
        } catch (err) {
          context.flash(err.message, 'error')
        }
      },
    }),
  ])
}

function newTaskDialog (context, data) {
  const { project, defaults, scanTypes, engines, discoveryProfiles } = data

  const target = input({ id: 'nt-target', placeholder: '10.0.0.0/24', required: 'required' })
  const name = input({ id: 'nt-name', placeholder: 'optional — defaults to the target' })
  const scanType = select({ id: 'nt-type' },
    Object.entries(scanTypes).map(([value, label]) => ({ value, label, selected: value === 'full' })))
  const engine = select({ id: 'nt-engine' },
    Object.entries(engines).map(([value, info]) =>
      ({ value, label: info.label, selected: value === defaults.engine })))
  const discovery = select({ id: 'nt-disc' }, [
    { value: '', label: 'Skip discovery — scan every address' },
    ...discoveryProfiles.map((profile) => ({
      value: profile.key, label: profile.label, selected: profile.key === defaults.discovery,
    })),
  ])
  const tcp = input({ id: 'nt-tcp', value: defaults.tcp })
  const udp = input({ id: 'nt-udp', placeholder: 'blank = skip' })
  const topPorts = input({ id: 'nt-top', type: 'number', min: '1', max: '65535', value: String(defaults.top_ports) })
  const rate = input({ id: 'nt-rate', type: 'number', min: '100', value: String(defaults.rate) })
  const retries = input({ id: 'nt-retries', type: 'number', min: '0', max: '10', value: String(defaults.retries) })
  const notes = el('textarea.input', { id: 'nt-notes', rows: 2, placeholder: 'optional' })

  const engineNote = el('p.hint')
  const fullOnly = el('div',
    field('Engine', engine, null), engineNote,
    el('div.grid-2', field('TCP ports', tcp), field('UDP ports', udp)),
    el('div.grid-2', field('Rate (pkts/s)', rate), field('Retries', retries)))
  const quickOnly = el('div', field('Top ports', topPorts,
    'Or set an explicit TCP range above to scan exactly those.'))

  const syncType = () => {
    const type = scanType.value
    fullOnly.hidden = type !== 'full'
    quickOnly.hidden = type !== 'quick'
  }
  const syncEngine = () => { engineNote.textContent = engines[engine.value]?.note || '' }
  scanType.addEventListener('change', syncType)
  engine.addEventListener('change', syncEngine)
  syncType(); syncEngine()

  const { close } = context.dialog('New scan task', [
    field('Target (IP, CIDR or range)', target),
    field('Name', name),
    el('div.grid-2', field('Scan type', scanType), field('Discovery', discovery)),
    fullOnly, quickOnly,
    field('Notes', notes),
  ], () => [
    button('Create', {
      kind: 'btn-secondary',
      onclick: () => submit(false),
    }),
    button('Create and start', {
      kind: 'btn-primary',
      iconName: 'play',
      onclick: () => submit(true),
    }),
  ])

  async function submit (start) {
    try {
      const form = {
        target: target.value, name: name.value, notes: notes.value,
        scan_type: scanType.value, discovery: discovery.value,
        engine: engine.value, tcp_ports: tcp.value, udp_ports: udp.value,
        rate: rate.value, retries: retries.value, top_ports: topPorts.value,
      }
      const { taskId } = await api.tasks.create(project.id, form)
      close()
      if (start) await api.scan.start(taskId)
      context.go(`tasks/${taskId}`)
    } catch (err) {
      context.flash(err.message, 'error')
    }
  }
}

export { shortDate }
