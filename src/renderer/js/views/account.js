'use strict'
/** The account page: who is signed in, and changing the password. */
import { api } from '../api.js'
import { el, button, field, input } from '../dom.js'

export async function renderAccount (context) {
  const [status, info, caps] = await Promise.all([
    api.auth.status(), api.info(), api.scan.capabilities(),
  ])

  const current = input({ id: 'ac-cur', type: 'password', autocomplete: 'current-password' })
  const next = input({ id: 'ac-new', type: 'password', autocomplete: 'new-password' })
  const confirm = input({ id: 'ac-con', type: 'password', autocomplete: 'new-password' })

  const capBox = el('div.stack')

  const drawCaps = (state) => {
    capBox.replaceChildren(...Object.entries(state.tools).map(([tool, info]) => {
      const actions = el('div.host-actions')
      let status

      if (!info.installed) {
        status = el('span.cell-muted', { text: 'not installed' })
      } else if (info.usable) {
        status = el('span.tag.tag-ok', {
          text: info.via || (state.root ? 'root' : 'ambient'),
        })
        // Revoking is always offered: it only ever removes privilege.
        if (info.via === 'capability') {
          actions.append(button('Revoke', {
            kind: 'btn-ghost',
            onclick: () => act(() => api.scan.revoke(tool)),
          }))
        }
      } else if (info.missing) {
        status = el('span.tag.tag-pause', { text: `partial — missing ${info.missing.join(', ')}` })
      } else {
        status = el('span.tag.tag-bad', { text: 'no raw sockets' })
      }

      if (info.installed && !info.usable && info.grantable && state.canGrant) {
        actions.append(button('Grant', {
          kind: 'btn-secondary',
          onclick: () => act(() => api.scan.grant(tool)),
        }))
      }

      return el('div.card.elev-sm.note-row',
        el('div.note-body',
          el('div.note-head', el('span.mono', { text: tool }), status),
          // Only when something needs doing: the equivalent command, for anyone
          // who would rather run it themselves than click Grant.
          info.installed && !info.usable
            ? el('p.hint', { text: info.grantCommand })
            : null),
        actions)
    }))
  }

  const act = async (fn) => {
    try {
      const result = await fn()
      context.flash(result.message, result.ok ? 'ok' : 'error')
      drawCaps(result.state)
    } catch (err) {
      context.flash(err.message, 'error')
    }
  }
  drawCaps(caps)

  return el('div.wrap',
    el('div.page-head', el('div',
      el('h3', { text: 'Account' }),
      el('p.sub', { text: `Signed in as ${status.username}` }))),

    el('h6.card-kicker.section-head', { text: 'Change password' }),
    el('div.card.elev-sm.card-pad.section',
      field('Current password', current),
      field('New password', next, `At least ${status.minLength} characters.`),
      field('Confirm new password', confirm),
      el('div.dialog-actions', button('Change password', {
        kind: 'btn-primary',
        onclick: async () => {
          try {
            await api.auth.changePassword(current.value, next.value, confirm.value)
            current.value = next.value = confirm.value = ''
            context.flash('Password changed.')
          } catch (err) {
            context.flash(err.message, 'error')
          }
        },
      }))),

    el('h6.card-kicker.section-head', { text: 'Scanner privileges' }),
    capBox,
    el('p.hint', {
      text: 'These need raw sockets. Granting the capability keeps them running ' +
            'as your own user, so pause and stop still work. Revoke takes it back.',
    }),

    el('h6.card-kicker.section-head', { text: 'About' }),
    el('div.card.elev-sm.table-card',
      el('table.table', el('tbody',
        ...Object.entries({
          Version: info.version,
          'Data directory': info.dataDir,
          Database: info.dbPath,
          Electron: info.electron,
          Node: info.node,
        }).map(([key, value]) =>
          el('tr', el('td.cell-muted', { text: key }), el('td.mono', { text: String(value) })))))))
}
