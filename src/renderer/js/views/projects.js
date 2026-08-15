'use strict'
/** The dashboard: every project, with rolled-up counts. */
import { api } from '../api.js'
import { el, icon, button, field, input, select } from '../dom.js'

export async function renderProjects (context) {
  let show = 'active'
  const wrap = el('div.wrap')

  async function draw () {
    const { projects, archived, activeTask } = await api.projects.list(
      show === 'all' ? null : show)

    const actions = el('div.page-actions')
    if (show === 'active' && archived) {
      actions.append(button(`Show ${archived} archived`, {
        kind: 'btn-ghost',
        iconName: 'archive',
        onclick: () => { show = 'all'; redraw() },
      }))
    } else if (show !== 'active') {
      actions.append(button('Hide archived', {
        kind: 'btn-ghost',
        iconName: 'archive',
        onclick: () => { show = 'active'; redraw() },
      }))
    }
    actions.append(
      button('Import', {
        kind: 'btn-ghost',
        iconName: 'upload-simple',
        onclick: () => importInto(context, null, redraw),
      }),
      button('Quick scan', {
        kind: 'btn-secondary',
        iconName: 'lightning',
        onclick: () => quickScanDialog(context),
      }),
      button('New project', {
        kind: 'btn-primary',
        iconName: 'plus',
        onclick: () => context.newProjectDialog(),
      }))

    const body = [
      el('div.page-head',
        el('div',
          el('h3', { text: 'Projects' }),
          el('p.sub', { text: 'Every scan belongs to a project. Ad-hoc runs land in Quick scans.' })),
        actions),
    ]

    if (activeTask) {
      body.push(el('a.card.elev-sm.banner-live', { href: `#tasks/${activeTask}` },
        el('span.dot.dot-live'),
        el('span.banner-text', { text: 'A scan is running — open it' })))
    }

    const stack = el('div.stack')
    if (!projects.length) {
      stack.append(el('div.card.elev-sm.card-empty',
        el('p.sub', { text: 'No projects yet. Create one, or run a quick scan.' })))
    }
    for (const project of projects) {
      stack.append(el('a.card.elev-sm.row-card', { href: `#projects/${project.id}` },
        el('div.row-card-main',
          el('div.row-card-title',
            el('span.card-title', { text: project.name }),
            project.running_count
              ? el('span.tag.tag-run', { text: 'scanning' })
              : (project.status !== 'active'
                  ? el('span.tag.tag-neutral', { text: project.status })
                  : null)),
          project.client ? el('p.card-kicker.tight', { text: project.client }) : null,
          project.description ? el('p.sub.clamp', { text: project.description }) : null,
          el('p.card-meta.spaced', { text: `updated ${project.updated_at}` })),
        el('div.row-card-counts',
          count(project.task_count, 'tasks'),
          count(project.host_count, 'hosts'),
          count(project.finding_count, 'ports'))))
    }
    body.push(stack)
    return body
  }

  async function redraw () {
    const body = await draw()
    wrap.replaceChildren(...body)
  }

  wrap.replaceChildren(...await draw())
  return wrap
}

const count = (value, label) =>
  el('div', el('b', { text: String(value) }), ` ${label}`)

/** Import a bundle, either into a project or as a new one. */
export async function importInto (context, projectId, after) {
  try {
    const result = await api.report.import(projectId)
    if (!result.imported) return
    const parts = [['tasks', 'task(s)'], ['hosts', 'host(s)'], ['ports', 'port(s)'],
      ['scans', 'nmap scan(s)'], ['shots', 'screenshot(s)']]
      .filter(([key]) => result[key]).map(([key, label]) => `${result[key]} ${label}`)
    context.flash(
      `Imported ${parts.join(' · ') || 'nothing — the file had no results'} ` +
      `${result.created ? 'into a new project' : 'into this project'}.`)
    if (result.skipped) {
      context.flash(`${result.skipped} entr(y/ies) in the file were malformed and were skipped.`,
        'error')
    }
    if (after) await after()
    context.go(`projects/${result.project}`)
  } catch (err) {
    context.flash(err.message, 'error')
  }
}

/** Old-style one-shot scan: files itself under a 'Quick scans' project. */
function quickScanDialog (context) {
  const target = input({ id: 'q-target', placeholder: '10.0.0.0/24', required: 'required' })
  const tcp = input({ id: 'q-tcp', value: '1-65535' })
  const udp = input({ id: 'q-udp', placeholder: 'blank = skip' })
  const rate = input({ id: 'q-rate', type: 'number', min: '100', value: '1000' })
  const octet = input({ id: 'q-octet', type: 'number', min: '1', max: '254', placeholder: 'optional' })

  const { close } = context.dialog('Quick scan', [
    el('p.hint.dialog-hint', { text: 'Files itself under a “Quick scans” project.' }),
    field('Target (IP, CIDR or range)', target),
    el('div.grid-2', field('TCP ports', tcp), field('UDP ports', udp)),
    el('div.grid-2', field('Rate (pkts/s)', rate), field('Start IP (last octet)', octet)),
  ], () => [button('Start scan', {
    kind: 'btn-primary',
    iconName: 'play',
    onclick: async () => {
      try {
        const { projectId } = await api.projects.create({
          name: 'Quick scans', description: 'Ad-hoc scans started from the dashboard.',
        }).catch(async () => {
          // Already exists: find it rather than failing.
          const { projects } = await api.projects.list(null)
          const found = projects.find((p) => p.name === 'Quick scans')
          if (!found) throw new Error('Could not open the Quick scans project.')
          return { projectId: found.id }
        })
        const { taskId } = await api.tasks.create(projectId, {
          target: target.value, tcp_ports: tcp.value, udp_ports: udp.value,
          rate: rate.value, start_octet: octet.value, scan_type: 'full',
        })
        close()
        await api.scan.start(taskId)
        context.go(`tasks/${taskId}`)
      } catch (err) {
        context.flash(err.message, 'error')
      }
    },
  })])
}

export { select }
