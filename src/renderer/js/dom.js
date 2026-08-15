'use strict'
/** DOM helpers.
 *
 * Everything is built with createElement and textContent rather than
 * innerHTML. That is not fussiness: the strings going into these views are
 * service banners, hostnames, page titles and nmap output taken off hosts
 * under someone else's control. Jinja autoescaped them; here the equivalent
 * guarantee comes from never parsing them as markup in the first place.
 */

/** el('div.card.elev-sm', {attrs}, ...children) */
export function el (spec, attrs, ...children) {
  const [tag, ...classes] = String(spec).split('.')
  const node = document.createElement(tag || 'div')
  if (classes.length) node.className = classes.join(' ')

  // The second argument is attributes only when it is a plain object. An array
  // is a list of children — missing that turned `el('div', items.map(...))`
  // into a div with attributes named "0", "1", "2" and no content at all.
  const isAttrs = attrs && typeof attrs === 'object' &&
                  !Array.isArray(attrs) && !(attrs instanceof Node)
  if (attrs !== undefined && attrs !== null && !isAttrs) {
    children.unshift(attrs)
    attrs = null
  }
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue
    if (key === 'class') node.className = [node.className, value].filter(Boolean).join(' ')
    else if (key === 'text') node.textContent = value
    else if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value)
    } else if (key === 'dataset') Object.assign(node.dataset, value)
    else node.setAttribute(key, value)
  }
  append(node, children)
  return node
}

function append (node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue
    node.append(child instanceof Node ? child : document.createTextNode(String(child)))
  }
}

export const clear = (node) => { while (node.firstChild) node.firstChild.remove() }

export function replace (node, ...children) {
  clear(node)
  append(node, children)
  return node
}

/** A Phosphor icon. The font is local; the class name is all that is needed. */
export const icon = (name) => el('i', { class: `ph ph-${name}` })

export const tag = (text, kind = 'tag-neutral') => el('span', { class: `tag ${kind}`, text })

/** Status → the Nocturne tag colour, matching the Jinja tag_for map. */
export const STATUS_TAG = {
  running: 'tag-run',
  paused: 'tag-pause',
  completed: 'tag-ok',
  stopped: 'tag-bad',
  error: 'tag-bad',
  interrupted: 'tag-neutral',
  pending: 'tag-outline',
}

export const statusTag = (status) => tag(status, STATUS_TAG[status] || 'tag-neutral')

/** '2026-03-04 09:19:41' → '03-04 09:19', matching the shortdate filter. */
export const shortDate = (value) => String(value || '').slice(5, 16)

/** A labelled form field. */
export function field (label, control, hint) {
  return el('div.field', el('label', { for: control.id || null, text: label }), control,
    hint ? el('p.hint', { text: hint }) : null)
}

export function input (attrs) {
  return el('input.input', { type: 'text', ...attrs })
}

export function select (attrs, options) {
  const node = el('select.input', attrs)
  for (const { value, label, selected } of options) {
    node.append(el('option', { value, selected: selected ? 'selected' : null, text: label }))
  }
  return node
}

export function button (label, { kind = 'btn-secondary', iconName = null, ...attrs } = {}) {
  return el('button', { class: `btn ${kind}`, type: 'button', ...attrs },
    iconName ? icon(iconName) : null, label)
}
