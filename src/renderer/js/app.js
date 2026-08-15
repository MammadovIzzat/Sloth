'use strict'
/** Router, shell and the sign-in screens.
 *
 * The Flask build navigated between pages; there are no URLs here, so this is
 * a small hash router over the same set of views. The Nocturne markup is
 * unchanged — same classes, same structure — so the stylesheet did not have to
 * be touched, only the inline style attributes the CSP forbids.
 */
import { api } from './api.js'
import { el, clear, replace, icon, button, field, input } from './dom.js'
import { renderProjects } from './views/projects.js'
import { renderProject } from './views/project.js'
import { renderTask } from './views/task.js'
import { renderScans, renderScanResult } from './views/scans.js'
import { renderAccount } from './views/account.js'
import { renderNotifications } from './views/notifications.js'

const root = document.getElementById('root')

const ROUTES = [
  [/^$/, () => renderProjects(context)],
  [/^projects\/([^/]+)$/, (id) => renderProject(context, id)],
  [/^tasks\/([^/]+)$/, (id) => renderTask(context, id)],
  [/^scans$/, () => renderScans(context)],
  [/^scan\/([^/]+)$/, (id) => renderScanResult(context, id)],
  [/^account$/, () => renderAccount(context)],
  [/^notifications$/, () => renderNotifications(context)],
]

/** Passed to every view: navigation, flashes, and the shared event stream. */
export const context = {
  go (path) {
    if (location.hash === '#' + path) route()
    else location.hash = path
  },
  flash,
  refreshSidebar,
  refreshBadge,
}

// --- flashes --------------------------------------------------------------

function flash (message, kind = 'ok') {
  const bar = document.getElementById('flashes')
  const node = el(`div.flash.flash-${kind}`,
    icon(kind === 'ok' ? 'check-circle' : 'warning-circle'),
    el('span', { text: message }),
    el('a.flash-close', { href: '#', onclick: (e) => { e.preventDefault(); node.remove() } },
      icon('x')))
  bar.append(node)
  // Errors stay until dismissed; a confirmation does not need to linger.
  if (kind === 'ok') setTimeout(() => node.remove(), 6000)
}

// --- shell ----------------------------------------------------------------

/** The class names below are the ones base.html used, so nocturne.css and
 *  sloth.css style this sidebar without a single new rule. */
async function refreshSidebar () {
  const nav = document.getElementById('sidebar-projects')
  if (!nav) return
  const path = location.hash.replace(/^#/, '')
  try {
    const { projects } = await api.projects.list('active')
    replace(nav, ...projects.map((project) => el('a.side-project', {
      href: `#projects/${project.id}`,
      'aria-current': path === `projects/${project.id}` ? 'page' : null,
    }, el('span', { class: project.running_count ? 'dot dot-live' : 'dot' }),
    el('span.ellipsis', { text: project.name }))))
  } catch {
    clear(nav)
  }
}

function shell (username) {
  return el('div.shell',
    el('aside.sidebar',
      el('a.brand', { href: '#' },
        // The 64px file, not the large one: it is drawn small here, and that
        // variant is the one with the contrast lift that keeps it readable.
        el('img.brand-logo', { src: 'img/logo-small.png', alt: '' }),
        el('span.brand-word', { text: 'sloth' })),

      el('nav.nav.nav-stack',
        navLink('', 'folders', 'Projects'),
        navLink('scans', 'file-text', 'Saved nmap scans'),
        navLink('notifications', 'bell', 'Notifications', badge),
        navLink('account', 'user-circle', 'Account')),

      el('div.side-group',
        el('div.side-head',
          el('h6', { text: 'Projects' }),
          el('a', {
            href: '#',
            title: 'New project',
            onclick: (e) => { e.preventDefault(); newProjectDialog() },
          }, icon('plus'))),
        el('nav.nav.nav-stack', { id: 'sidebar-projects' })),

      el('div.side-foot',
        el('a.side-user', { href: '#account' }, icon('user'), username || ''),
        el('button.icon-link', {
          title: 'Sign out',
          onclick: async () => { await api.auth.logout(); boot() },
        }, icon('sign-out')))),

    el('main.main', el('div', { id: 'flashes', class: 'flashes' }), el('div', { id: 'view' })),
    el('div', { id: 'toasts', class: 'toasts' }))
}

function navLink (path, iconName, label, extra) {
  const active = (location.hash.replace(/^#/, '') || '') === path
  return el('a', { href: '#' + path, 'aria-current': active ? 'page' : null },
    icon(iconName), el('span.nav-label', { text: label }), extra || null)
}

// The unread count beside the sidebar's Notifications entry.
const badge = el('span.nav-badge.hidden')

async function refreshBadge () {
  try {
    const { unseen } = await api.notifications.list(1)
    badge.textContent = unseen > 99 ? '99+' : String(unseen)
    badge.classList.toggle('hidden', !unseen)
  } catch { /* signed out, or the window is closing */ }
}

/** A transient copy of a notification, on top of whatever page you are on.
 *
 * The toast is the disposable half: the entry is already in the log before
 * this runs, so dismissing one costs nothing.
 */
function toast (row) {
  const host = document.getElementById('toasts')
  if (!host) return
  const kind = { good: 'ok', bad: 'error', warn: 'error' }[row.level] || 'ok'
  const node = el(`div.flash.flash-${kind}.toast`,
    icon({ good: 'check-circle', warn: 'warning-circle', bad: 'x-circle' }[row.level] || 'info'),
    el('span.toast-text',
      el('b', { text: row.title }),
      row.message ? el('span', { text: ' ' + row.message }) : null),
    el('a.flash-close', {
      href: '#',
      onclick: (event) => { event.preventDefault(); node.remove() },
    }, icon('x')))
  if (row.task_id) {
    node.style.cursor = 'pointer'
    node.addEventListener('click', () => { node.remove(); context.go(`tasks/${row.task_id}`) })
  }
  host.append(node)
  // Failures stay until dismissed; the rest clear themselves.
  if (row.level !== 'bad') setTimeout(() => node.remove(), 9000)
  while (host.children.length > 4) host.firstChild.remove()
}

// --- auth screens ---------------------------------------------------------

function authScreen ({ title, subtitle, fields, submitLabel, onSubmit }) {
  const form = el('form.auth-fields')
  const controls = {}
  for (const spec of fields) {
    controls[spec.name] = input({ id: `f-${spec.name}`, type: spec.type || 'text',
      name: spec.name, autocomplete: spec.autocomplete || 'off', required: 'required' })
    form.append(field(spec.label, controls[spec.name], spec.hint))
  }
  const submit = el('button.btn.btn-primary.btn-wide', { type: 'submit' }, submitLabel)
  form.append(el('div.auth-actions', submit))

  // One slot that gets replaced, not the append-only flash list the rest of the
  // app uses. Stacking them pushed the form further down the screen with every
  // wrong password, and a second identical message says nothing the first did
  // not.
  const errorSlot = el('div.auth-error')
  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    submit.disabled = true
    clear(errorSlot)
    try {
      await onSubmit(Object.fromEntries(
        Object.entries(controls).map(([key, node]) => [key, node.value])))
    } catch (err) {
      replace(errorSlot,
        el('div.flash.flash-error',
          icon('warning-circle'),
          el('span', { text: err.message })))
      // Put the cursor back where the correction happens.
      const password = controls.password
      if (password) { password.focus(); password.select() }
    } finally {
      submit.disabled = false
    }
  })

  // Two columns, as the stylesheet expects: the form on the left, a quiet
  // panel on the right. Putting these straight into .auth (a flex row) is what
  // scattered them across the window.
  return el('div.auth',
    el('div.auth-form',
      // The sign-in screen has room, so the artwork gets shown at a size where
      // it can be read rather than reduced to a smudge.
      el('div.auth-brand',
        el('img.auth-logo', { src: 'img/logo.png', alt: '' }),
        el('span', { text: 'sloth' })),
      el('div.auth-inner',
        el('h3.auth-title', { text: title }),
        el('p.sub.auth-sub', { text: subtitle }),
        el('div', { id: 'flashes', class: 'flashes' }),
        errorSlot,
        form)),
    el('aside.auth-aside',
      el('p', {
        text: 'Sloth runs entirely on this machine. No listening port, no ' +
              'browser, nothing to reach from the network. Scanners that need ' +
              'raw sockets are granted the capability individually.',
      })))
}

function loginScreen () {
  return authScreen({
    title: 'Sign in',
    subtitle: 'This database holds client scan results. It stays locked until you sign in.',
    fields: [
      { name: 'username', label: 'Username', autocomplete: 'username' },
      { name: 'password', label: 'Password', type: 'password', autocomplete: 'current-password' },
    ],
    submitLabel: 'Sign in',
    onSubmit: async ({ username, password }) => {
      await api.auth.login(username, password)
      boot()
    },
  })
}

function setupScreen (minLength) {
  return authScreen({
    title: 'Create your account',
    subtitle: 'There is no default password — the first account is the one you make now.',
    fields: [
      { name: 'username', label: 'Username', autocomplete: 'username' },
      {
        name: 'password',
        label: 'Password',
        type: 'password',
        autocomplete: 'new-password',
        hint: `At least ${minLength} characters.`,
      },
      { name: 'confirm', label: 'Confirm password', type: 'password', autocomplete: 'new-password' },
    ],
    submitLabel: 'Create account',
    onSubmit: async ({ username, password, confirm }) => {
      await api.auth.setup(username, password, confirm)
      boot()
    },
  })
}

// --- new-project dialog ---------------------------------------------------

export function dialog (title, body, actions) {
  const backdrop = el('div.dialog-backdrop')
  const close = () => backdrop.remove()
  const panel = el('div.dialog',
    el('div.row-between',
      el('span.dialog-title', { text: title }),
      el('a.dialog-x', { href: '#', onclick: (e) => { e.preventDefault(); close() } }, icon('x'))),
    el('div.dialog-body', body),
    el('div.dialog-actions',
      button('Cancel', { kind: 'btn-ghost', onclick: close }),
      ...actions(close)))
  backdrop.append(panel)
  backdrop.addEventListener('click', (event) => { if (event.target === backdrop) close() })
  document.addEventListener('keydown', function esc (event) {
    if (event.key === 'Escape') { close(); document.removeEventListener('keydown', esc) }
  })
  document.body.append(backdrop)
  const first = panel.querySelector('input, select, textarea')
  if (first) first.focus()
  return { close, panel }
}

function newProjectDialog () {
  const name = input({ id: 'np-name', placeholder: 'Acme Corp — internal' })
  const client = input({ id: 'np-client', placeholder: 'optional' })
  const description = el('textarea.input', {
    id: 'np-desc', rows: 3, placeholder: 'Engagement notes, rules of engagement, …',
  })
  const { close } = dialog('New project',
    [field('Name', name), field('Client / scope', client), field('Description', description)],
    () => [button('Create project', {
      kind: 'btn-primary',
      onclick: async () => {
        try {
          const { projectId } = await api.projects.create({
            name: name.value, client: client.value, description: description.value,
          })
          close()
          await refreshSidebar()
          context.go(`projects/${projectId}`)
        } catch (err) {
          flash(err.message, 'error')
        }
      },
    })])
}

context.dialog = dialog
context.newProjectDialog = newProjectDialog

// --- routing --------------------------------------------------------------

async function route () {
  const view = document.getElementById('view')
  if (!view) return
  const path = location.hash.replace(/^#/, '')
  for (const [pattern, render] of ROUTES) {
    const match = pattern.exec(path)
    if (!match) continue
    clear(view)
    try {
      const node = await render(...match.slice(1))
      replace(view, node)
    } catch (err) {
      replace(view, el('div.card.elev-sm.card-pad',
        el('h4', { text: 'Could not open this page' }),
        el('p.sub', { text: err.message })))
    }
    // Re-mark the active link the way the stylesheet expects.
    document.querySelectorAll('.nav a').forEach((node) => {
      const target = (node.getAttribute('href') || '').replace(/^#/, '')
      if (target === path) node.setAttribute('aria-current', 'page')
      else node.removeAttribute('aria-current')
    })
    refreshSidebar()
    return
  }
  replace(view, el('div.card.elev-sm.card-pad', el('p.sub', { text: 'Nothing here.' })))
}

window.addEventListener('hashchange', route)

// --- boot -----------------------------------------------------------------

async function boot () {
  clear(root)
  let status
  try {
    status = await api.auth.status()
  } catch (err) {
    root.append(el('div.auth', el('p.sub', { text: 'Sloth could not start: ' + err.message })))
    return
  }

  if (status.needsSetup) return root.append(setupScreen(status.minLength))
  if (!status.signedIn) return root.append(loginScreen())

  root.append(shell(status.username))

  // Running as root means no Chromium sandbox. That is a deliberate choice, but
  // it should not be an invisible one — a banner is cheap and easy to miss the
  // absence of.
  try {
    const info = await api.info()
    if (info.uid === 0) {
      document.getElementById('flashes').append(
        el('div.flash.flash-error',
          icon('warning-circle'),
          el('span', {
            text: 'Running as root — the interface is unsandboxed.',
          })))
    }
  } catch { /* the banner is not worth failing startup over */ }

  await refreshSidebar()
  await refreshBadge()
  await route()

  // One subscription for the whole session, not one per page.
  if (!boot.subscribed) {
    boot.subscribed = true
    api.onNotification(({ notification, unseen }) => {
      badge.textContent = unseen > 99 ? '99+' : String(unseen)
      badge.classList.toggle('hidden', !unseen)
      toast(notification)
    })
  }
}

boot()
