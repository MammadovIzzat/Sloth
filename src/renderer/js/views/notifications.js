'use strict'
/** The notification log: everything that has been raised, oldest kept.
 *
 * Dismissing a toast hides it; it never deletes it. This page is where you come
 * back to read what a long sweep did while you were elsewhere, so the only
 * thing that removes an entry is asking for it explicitly.
 */
import { api } from '../api.js'
import { el, icon, button, shortDate } from '../dom.js'

const LEVEL_ICON = { good: 'check-circle', warn: 'warning-circle', bad: 'x-circle', info: 'info' }
const LEVEL_TAG = { good: 'tag-ok', warn: 'tag-pause', bad: 'tag-bad', info: 'tag-neutral' }

export async function renderNotifications (context) {
  const list = el('div.stack')
  const summary = el('p.sub')
  const wrap = el('div.wrap')

  async function draw () {
    const { notifications, unseen } = await api.notifications.list(200)
    summary.textContent = notifications.length
      ? `${notifications.length} entr${notifications.length === 1 ? 'y' : 'ies'}` +
        (unseen ? `, ${unseen} unread.` : '.')
      : 'Nothing yet. Scan activity will appear here.'

    list.replaceChildren(...(notifications.length
      ? notifications.map((row) => {
        const body = el('div.note-body',
          el('div.note-head',
            el('span.card-title.small', { text: row.title }),
            el('span', { class: `tag ${LEVEL_TAG[row.level] || 'tag-neutral'}`, text: row.level }),
            row.seen ? null : el('span.note-dot', { title: 'unread' })),
          row.message ? el('p.sub.spaced-sm', { text: row.message }) : null,
          el('p.card-meta.spaced-sm', { text: row.created_at }))

        // Entries tied to a task link back to it; the rest are just a record.
        return row.task_id
          ? el('a.card.elev-sm.note-row', { href: `#tasks/${row.task_id}` },
            icon(LEVEL_ICON[row.level] || 'info'), body)
          : el('div.card.elev-sm.note-row',
            icon(LEVEL_ICON[row.level] || 'info'), body)
      })
      : [el('div.card.elev-sm.card-empty',
          el('p.sub', { text: 'No notifications yet.' }))]))
  }

  wrap.append(
    el('div.page-head',
      el('div', el('h3', { text: 'Notifications' }), summary),
      el('div.page-actions',
        button('Mark all read', {
          kind: 'btn-ghost',
          iconName: 'check',
          onclick: async () => {
            await api.notifications.markSeen(null)
            await draw()
            await context.refreshBadge()
          },
        }),
        button('Clear log', {
          kind: 'btn-ghost',
          iconName: 'trash',
          onclick: () => {
            const { close } = context.dialog('Clear the notification log?', [
              el('p.sub', {
                text: 'Every entry is deleted. Scan results, reports and findings ' +
                      'are untouched — this only removes the activity record.',
              }),
            ], (closeIt) => [button('Clear', {
              kind: 'btn-danger',
              onclick: async () => {
                await api.notifications.clear()
                closeIt()
                await draw()
                await context.refreshBadge()
              },
            })])
            void close
          },
        }))),
    list)

  await draw()
  // Opening the log is reading it, so the badge clears — but the entries stay.
  await api.notifications.markSeen(null)
  await context.refreshBadge()
  return wrap
}
