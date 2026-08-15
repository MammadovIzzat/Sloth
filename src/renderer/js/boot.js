'use strict'
/* Scaffold check: proves the preload bridge is wired and the Nocturne assets
   load from disk under the CSP. Replaced by the real router once the pages
   are ported. */
;(async () => {
  const boot = document.getElementById('boot')
  const info = document.getElementById('info')
  try {
    const res = await window.sloth.call('app:info')
    if (!res.ok) throw new Error(res.error)
    boot.textContent = 'main process reachable over IPC'
    for (const [key, value] of Object.entries(res.data)) {
      const row = document.createElement('tr')
      const label = document.createElement('td')
      label.textContent = key
      label.className = 'cell-muted'
      const cell = document.createElement('td')
      cell.textContent = String(value)
      row.append(label, cell)
      info.append(row)
    }
    // The bridge must expose exactly what preload allows and nothing more.
    const leaked = ['require', 'process', 'module', 'ipcRenderer']
      .filter((name) => name in window)
    const row = document.createElement('tr')
    row.innerHTML = '<td class="cell-muted">node leaked into renderer</td>'
    const cell = document.createElement('td')
    cell.textContent = leaked.length ? leaked.join(', ') : 'no'
    row.append(cell)
    info.append(row)
  } catch (err) {
    boot.textContent = 'bridge failed: ' + err.message
  }
})()
