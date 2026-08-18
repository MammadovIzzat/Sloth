/* Live scan view: subscribes to the task's SSE stream and updates host cards.
   The page is already rendered with everything the database knows, so this only
   has to apply deltas — a reload mid-scan never loses results. */
(function () {
    "use strict";

    const cardsView = document.getElementById("resultsCards");
    const tableView = document.getElementById("resultsTable");
    const rowsBody  = document.getElementById("resultsRows");
    const emptyBox  = document.getElementById("emptyState");
    const logBox    = document.getElementById("logBox");
    const badge     = document.getElementById("statusBadge");
    const startBtn  = document.getElementById("startBtn");
    const pauseBtn  = document.getElementById("pauseBtn");
    const stopBtn   = document.getElementById("stopBtn");
    const resumeFileBtn = document.getElementById("resumeFileBtn");
    const alertBox  = document.getElementById("networkAlertBox");
    const progressWrap  = document.getElementById("progressWrap");
    const progressBar   = document.getElementById("progressBar");
    const progressLabel = document.getElementById("progressLabel");
    const rateLabel     = document.getElementById("rateLabel");
    const hostCountEl   = document.getElementById("hostCount");
    const phaseEl       = document.getElementById("phaseBadge");

    // Nocturne tag variants; each scan state keeps its own hue.
    const BADGES = {
        running: "tag-run", paused: "tag-pause", completed: "tag-ok",
        stopped: "tag-bad", error: "tag-bad",
        interrupted: "tag-neutral", pending: "tag-outline"
    };

    let source = null;
    let state  = window.TASK.status;
    const hostCards = new Map();

    document.querySelectorAll("#resultsCards [data-ip]").forEach(function (card) {
        hostCards.set(card.dataset.ip, card);
        addActions(card, card.dataset.ip);
    });
    // Server-rendered table rows: give each host its rescan control.
    if (rowsBody) {
        const seen = {};
        rowsBody.querySelectorAll("tr[data-ip]").forEach(function (r) {
            if (!seen[r.dataset.ip]) { seen[r.dataset.ip] = 1; ensureTableAction(r.dataset.ip); }
        });
    }
    updateHostCount();

    // Reattach to any rescan that was still running when the page loaded.
    Object.keys(window.TASK.rescanning || {}).forEach(function (ip) {
        const card = hostCards.get(ip);
        if (card) { markRescanning(card, window.TASK.rescanning[ip]); }
    });

    // --- rendering -------------------------------------------------------

    function setStatus(next) {
        state = next;
        badge.className = "tag " + (BADGES[next] || BADGES.pending);
        badge.innerText = next;

        const dot = document.getElementById("logDot");
        if (dot) {
            dot.classList.toggle("dot-live", next === "running");
            dot.style.background = next === "running" ? ""
                : (next === "error" || next === "stopped") ? "#f2555a"
                : next === "completed" ? "#3fb984" : "";
        }
        const live = next === "running" || next === "paused";
        if (!live && phaseEl) { phaseEl.classList.add("hidden"); }
        startBtn.classList.toggle("hidden", live);
        pauseBtn.classList.toggle("hidden", !live);
        stopBtn.classList.toggle("hidden", !live);
        progressWrap.classList.toggle("hidden", !live);
        pauseBtn.innerText = next === "paused" ? "RESUME" : "PAUSE";
        startBtn.innerText = next === "pending" ? "START" : "RUN AGAIN";
    }

    function setResumable(canResume) {
        resumeFileBtn.classList.toggle("hidden", !canResume || state === "running" || state === "paused");
    }

    function log(line) {
        logBox.textContent += line + "\n";
        logBox.scrollTop = logBox.scrollHeight;
    }

    function updateHostCount() {
        hostCountEl.innerText = hostCards.size ? "(" + hostCards.size + ")" : "";
        emptyBox.classList.toggle("hidden", hostCards.size > 0);
    }

    function setPhase(phase, label) {
        if (!phaseEl) { return; }
        if (phase === "discovery") {
            phaseEl.className = "tag tag-accent";
            phaseEl.innerText = "🔎 discovering hosts" + (label ? " · " + label : "");
        } else {
            phaseEl.className = "tag tag-run";
            phaseEl.innerText = "⚡ port scan" + (label ? " · " + label : "");
        }
        phaseEl.classList.remove("hidden");
    }

    // A discovered host gets a card straight away, before any port is known —
    // that is the entire output of a discovery-only scan.
    function markAlive(ev) {
        const card = cardFor(ev.ip);
        const holder = card.querySelector(".host-meta");
        const bits = [];
        if (ev.hostname) { bits.push(ev.hostname); }
        if (ev.reason) { bits.push(ev.reason); }
        if (holder && bits.length) { holder.innerText = bits.join(" · "); }
        const ports = card.querySelector(".ports-container");
        if (ports && !ports.querySelector("[data-port]") && !ports.dataset.alive) {
            ports.dataset.alive = "1";
            ports.innerHTML = '<span class="host-empty">host is up — no ports scanned yet</span>';
        }
        updateHostCount();
    }

    function cardFor(ip) {
        let card = hostCards.get(ip);
        if (card) { return card; }

        card = document.createElement("div");
        card.className = "host card elev-sm host-card";
        card.dataset.ip = ip;
        card.innerHTML =
            '<div class="host-head">' +
              '<div class="host-id">' +
                '<span class="host-ip"></span><span class="host-meta"></span>' +
              '</div>' +
              '<div class="host-actions"></div>' +
            '</div>' +
            '<div class="ports ports-container"></div>';
        card.querySelector(".host-ip").innerText = ip;
        cardsView.appendChild(card);
        hostCards.set(ip, card);
        addActions(card, ip);
        updateHostCount();
        return card;
    }

    function addPort(ip, port) {
        const key = port.port + "/" + port.proto;
        upsertCardPill(ip, port, key);
        upsertTableRow(ip, port, key);
    }

    // Cards view — a neutral pill per port, matching the design: port number in
    // the accent, service muted beside it.
    function upsertCardPill(ip, port, key) {
        const card = cardFor(ip);
        const container = card.querySelector(".ports-container");
        if (container.dataset.alive) {
            container.innerHTML = "";      // clear "host is up, no ports yet"
            delete container.dataset.alive;
        }
        let pill = container.querySelector('[data-port="' + CSS.escape(key) + '"]');
        if (!pill) {
            pill = document.createElement("span");
            pill.dataset.port = key;
            pill.className = "tag tag-neutral port";
            container.appendChild(pill);
        }
        if (String(port.state || "open").indexOf("open") !== 0) {
            pill.classList.add("port-filtered");
        }
        pill.title = (port.state || "open") + (port.source ? " · found by " + port.source : "");
        pill.innerHTML = "";
        const num = document.createElement("span");
        num.className = "port-num";
        num.innerText = key;
        pill.appendChild(num);
        if (port.service) {
            const svc = document.createElement("span");
            svc.className = "port-svc";
            svc.innerText = port.service;
            pill.appendChild(svc);
        }
        updateHostMeta(card);
    }

    // Table view — one row per port, so a large sweep stays readable.
    function upsertTableRow(ip, port, key) {
        if (!rowsBody) { return; }
        let row = rowsBody.querySelector('tr[data-ip="' + CSS.escape(ip)
                  + '"][data-port="' + CSS.escape(key) + '"]');
        if (!row) {
            row = document.createElement("tr");
            row.className = "host-row";
            row.dataset.ip = ip;
            row.dataset.port = key;
            row.innerHTML = '<td class="cell-ip"></td><td class="cell-port"></td>'
                          + '<td class="cell-svc"></td><td class="cell-src"></td>'
                          + '<td class="cell-actions"></td>';
            rowsBody.appendChild(row);
        }
        const cells = row.children;
        cells[0].innerText = ip;
        cells[1].innerText = key;
        cells[2].innerText = port.service || "\u2014";
        cells[3].innerText = port.source || "";
        ensureTableAction(ip);
    }

    function updateHostMeta(card) {
        const meta = card.querySelector(".host-meta");
        if (!meta) { return; }
        const n = card.querySelectorAll(".ports-container [data-port]").length;
        const found = meta.dataset.found || "";
        meta.innerText = [found, n ? n + " ports" : ""].filter(Boolean).join(" · ");
    }

    function renderPorts(ip, ports) {
        const card = cardFor(ip);
        const container = card.querySelector(".ports-container");
        container.innerHTML = "";
        delete container.dataset.alive;
        if (rowsBody) {
            rowsBody.querySelectorAll('tr[data-ip="' + CSS.escape(ip) + '"]')
                .forEach(function (r) { r.remove(); });
        }
        if (!ports || !ports.length) {
            container.dataset.alive = "1";
            container.innerHTML = '<span class="host-empty">host is up — no open ports recorded</span>';
            updateHostMeta(card);
            return;
        }
        ports.forEach(function (p) { addPort(ip, p); });
    }

    // --- per-host rescan --------------------------------------------------

    // The tool picker + Rescan button for one host. Built from the list the
    // server sends, so the menu and the code that runs it stay in step; a tool
    // that is not installed stays listed but unpickable. `card` is the host's
    // card, which the rescan/stop bookkeeping keys on even when the click came
    // from the table.
    function buildRescanControl(card, ip) {
        const select = document.createElement("select");
        select.className = "input host-tool";
        select.title = "Rescan this host with the selected tool.";
        (window.TASK.rescanTools || []).forEach(function (t) {
            const o = document.createElement("option");
            o.value = t.key;
            o.innerText = t.available ? t.label : t.label + " — " + t.tool + " not installed";
            o.title = t.available ? t.note : t.tool + " is not installed";
            if (!t.available) { o.disabled = true; }
            select.appendChild(o);
        });
        const btn = document.createElement("button");
        btn.className = "btn btn-secondary rescan-btn";
        btn.innerText = "🔄 Rescan";
        btn.onclick = function () { rescan(card, ip, select.value); };
        const wrap = document.createElement("span");
        wrap.className = "rescan-control";
        wrap.appendChild(select);
        wrap.appendChild(btn);
        return wrap;
    }

    function addActions(card, ip) {
        const holder = card.querySelector(".host-actions");
        if (!holder || holder.dataset.ready) { return; }
        holder.dataset.ready = "1";
        holder.appendChild(buildRescanControl(card, ip));
    }

    // The same control in the table view — one per host, on its first row, so a
    // long sweep in the default table view can still rescan a specific IP.
    function ensureTableAction(ip) {
        if (!rowsBody) { return; }
        const row = rowsBody.querySelector('tr[data-ip="' + CSS.escape(ip) + '"]');
        if (!row) { return; }
        let cell = row.querySelector(".cell-actions");
        if (!cell) { return; }
        // Move any control off a stale first row (rows for a host can be rebuilt
        // by renderPorts) and onto the current one.
        rowsBody.querySelectorAll('tr[data-ip="' + CSS.escape(ip) + '"] .cell-actions.has-control')
            .forEach(function (c) {
                if (c !== cell) { c.innerHTML = ""; c.classList.remove("has-control"); }
            });
        if (cell.dataset.ready) { return; }
        cell.dataset.ready = "1";
        cell.classList.add("has-control");
        cell.appendChild(buildRescanControl(cardFor(ip), ip));
    }

    function markRescanning(card, tool) {
        card.className = "host card elev-sm card-rescanning";
        const holder = card.querySelector(".host-actions");
        const btn = holder && holder.querySelector(".rescan-btn");
        if (btn) {
            btn.disabled = true;
            btn.innerText = "⏳ " + (tool || "").replace("_", " ") + "…";
        }
        // A deep nmap plus screenshots can run for many minutes; there has to be
        // a way out that doesn't take down the sweep or the other hosts.
        if (holder && !holder.querySelector(".rescan-stop")) {
            const stop = document.createElement("button");
            stop.className = "btn btn-ghost rescan-stop";
            stop.innerText = "✕ Stop";
            stop.onclick = function () { stopRescan(card, card.dataset.ip, stop); };
            holder.appendChild(stop);
        }
        // Also show it in the view-independent strip, so a running rescan is
        // stoppable from the table view too (the card controls only exist in
        // the cards view, which is not the default).
        addStripEntry(card.dataset.ip, tool);
    }

    function clearRescanning(card, ok) {
        card.className = ok ? "host card elev-sm" : "host card elev-sm card-failed";
        const holder = card.querySelector(".host-actions");
        const btn = holder && holder.querySelector(".rescan-btn");
        if (btn) {
            btn.disabled = false;
            btn.innerText = "🔄 Rescan";
        }
        const stop = holder && holder.querySelector(".rescan-stop");
        if (stop) { stop.remove(); }
        removeStripEntry(card.dataset.ip);
    }

    // --- the always-visible active-rescans strip --------------------------
    const strip = document.getElementById("activeRescans");

    function addStripEntry(ip, tool) {
        if (!strip || strip.querySelector('[data-strip-ip="' + CSS.escape(ip) + '"]')) { return; }
        const row = document.createElement("div");
        row.className = "rescan-strip-row";
        row.setAttribute("data-strip-ip", ip);
        const label = document.createElement("span");
        label.innerHTML = "<span class=\"dot dot-live\"></span> Rescanning <b>" +
            ip + "</b> · " + (tool || "").replace(/_/g, " ");
        const stop = document.createElement("button");
        stop.className = "btn btn-ghost rescan-strip-stop";
        stop.innerText = "✕ Stop";
        stop.onclick = function () {
            stop.disabled = true;
            stop.innerText = "✕ Stopping…";
            requestStop(ip);
        };
        row.appendChild(label);
        row.appendChild(stop);
        strip.appendChild(row);
        strip.classList.remove("hidden");
    }

    function removeStripEntry(ip) {
        if (!strip) { return; }
        const row = strip.querySelector('[data-strip-ip="' + CSS.escape(ip) + '"]');
        if (row) { row.remove(); }
        if (!strip.children.length) { strip.classList.add("hidden"); }
    }

    // The POST itself, shared by the card button and the strip button — the
    // result comes back over the event stream and clears both.
    function requestStop(ip) {
        fetch("/tasks/" + window.TASK.id + "/rescan/stop", {
            method: "POST",
            headers: {"Content-Type": "application/json", "X-CSRF-Token": window.TASK.csrf},
            body: JSON.stringify({ip: ip})
        })
        .then(function (r) { return r.json().then(function (d) { return {ok: r.ok, data: d}; }); })
        .then(function (res) {
            if (!res.ok) { log("stop " + ip + ": " + (res.data.error || "failed")); }
        })
        .catch(function (err) { log("stop " + ip + " failed: " + err); });
    }

    function stopRescan(card, ip, button) {
        button.disabled = true;
        button.innerText = "✕ Stopping…";
        requestStop(ip);
    }

    // Fire and forget: the request returns immediately and the result comes back
    // over the event stream, so a slow nmap can't time the browser out.
    function rescan(card, ip, tool) {
        markRescanning(card, tool);
        fetch("/tasks/" + window.TASK.id + "/rescan", {
            method: "POST",
            headers: {"Content-Type": "application/json", "X-CSRF-Token": window.TASK.csrf},
            body: JSON.stringify({ip: ip, tool: tool})
        })
        .then(function (r) { return r.json().then(function (d) { return {ok: r.ok, data: d}; }); })
        .then(function (res) {
            if (!res.ok || res.data.error) {
                clearRescanning(card, false);
                log("rescan " + ip + " rejected: " + (res.data.error || "unknown error"));
            }
        })
        .catch(function (err) {
            clearRescanning(card, false);
            log("rescan " + ip + " failed: " + err);
        });
    }

    function onRescanEvent(ev) {
        const card = hostCards.get(ev.ip);
        if (!card) { return; }
        if (ev.state === "running") { markRescanning(card, ev.tool); return; }
        if (ev.state === "error") {
            clearRescanning(card, false);
            log("rescan " + ev.ip + " failed: " + ev.error);
            return;
        }
        if (ev.state === "cancelled") {
            // Stopped during the nmap scan — nothing partial was kept.
            clearRescanning(card, true);
            log(ev.message || ("rescan " + ev.ip + " stopped"));
            return;
        }
        clearRescanning(card, true);
        renderPorts(ev.ip, ev.ports);
        if (ev.scan_id) { addReportLink(card, ev.ip, ev); }
        if (ev.note) { log(ev.ip + ": " + ev.note); }
        if (ev.stopped) { log("rescan " + ev.ip + " stopped — nmap results kept."); }
    }

    function addReportLink(card, ip, data) {
        const holder = card.querySelector(".host-actions");
        const old = holder.querySelector(".nmap-report-btn");
        if (old) { old.remove(); }
        const link = document.createElement("a");
        link.className = "btn btn-ghost nmap-report-btn";
        link.href = "/nmap-result/" + data.scan_id;
        link.target = "_blank";
        link.innerText = data.screenshots ? "📄 Report (📸 " + data.screenshots + ")" : "📄 Report";
        holder.appendChild(link);

        const list = document.getElementById("nmapList");
        if (list) {
            const entry = document.createElement("a");
            entry.className = "ellipsis";
            entry.href = link.href;
            entry.innerText = ip + " · just now";
            list.prepend(entry);
        }
    }

    // --- network banner ---------------------------------------------------

    function showNetwork(event) {
        if (event.connected) {
            alertBox.className = "flash flash-ok";
            alertBox.innerHTML =
                '<div class="flex justify-between items-center gap-3 flex-wrap">' +
                  '<div><div class="text-sm font-bold">🟢 Network restored</div>' +
                  '<p class="text-xs text-slate-400 mt-1">Reconnected at ' + (event.reconnected_at || "") + '. Resume when ready.</p></div>' +
                  '<button id="netResume" class="btn btn-primary">▶ RESUME SCAN</button>' +
                '</div>';
            document.getElementById("netResume").onclick = function () {
                post("resume").then(function () {
                    setStatus("running");
                    alertBox.className = "hidden";
                });
            };
        } else {
            alertBox.className = "flash flash-error";
            alertBox.innerHTML =
                '<div class="text-sm font-bold">🚨 Network lost — scan paused automatically</div>' +
                '<p class="text-xs text-slate-400 mt-1">Disconnected at ' + (event.disconnected_at || "") + '. ' +
                'The scanner processes are frozen, not killed — nothing is lost.</p>';
            setStatus("paused");
        }
    }

    // --- streaming --------------------------------------------------------

    function connect() {
        if (source) { source.close(); }
        source = new EventSource("/tasks/" + window.TASK.id + "/stream");

        source.onmessage = function (msg) {
            const ev = JSON.parse(msg.data);
            switch (ev.type) {
                case "snapshot":
                    // Sent on connect so nothing found before we subscribed is missed.
                    ev.hosts.forEach(function (h) {
                        if (h.ports && h.ports.length) { renderPorts(h.ip, h.ports); }
                        else { cardFor(h.ip); }
                    });
                    updateHostCount();
                    break;
                case "phase":
                    setPhase(ev.phase, ev.label || ev.tool);
                    break;
                case "discovered":
                    markAlive(ev);
                    break;
                case "discovery_done":
                    log("Discovery finished: " + ev.count + " host(s) up.");
                    setPhase("portscan", null);
                    break;
                case "host":
                    addPort(ev.ip, ev.port);
                    break;
                case "progress":
                    progressBar.style.width = ev.percent + "%";
                    progressLabel.innerText = ev.percent.toFixed(2) + "% done" +
                        (ev.remaining ? " · " + ev.remaining + " remaining" : "");
                    rateLabel.innerText = ev.rate_kpps + " kpps" +
                        (ev.found !== null && ev.found !== undefined ? " · found " + ev.found : "");
                    break;
                case "status":
                    setStatus(ev.status);
                    if (ev.message) { log(ev.message); }
                    break;
                case "network":
                    showNetwork(ev);
                    break;
                case "rescan":
                    onRescanEvent(ev);
                    break;
                case "log":
                    log(ev.line);
                    break;
                case "done":
                    setStatus(ev.status);
                    setResumable(ev.resumable);
                    if (ev.error) { log("Error: " + ev.error); }
                    document.querySelectorAll(".card-scanning").forEach(function (el) {
                        el.classList.remove("card-scanning");
                    });
                    // Deliberately stay connected: rescans report over this same
                    // stream and can be started long after the sweep finishes.
                    break;
            }
        };
        source.onerror = function () {
            if (source) { source.close(); source = null; }
            // Reconnect: the stream is now the delivery channel for rescans too,
            // so losing it silently would strand a running rescan's result.
            setTimeout(function () { if (!source) { connect(); } }, 3000);
        };
    }

    // --- controls ---------------------------------------------------------

    function post(action) {
        return fetch("/tasks/" + window.TASK.id + "/" + action,
                     {method: "POST", headers: {"X-CSRF-Token": window.TASK.csrf}})
            .then(function (r) { return r.json().then(function (d) { return {ok: r.ok, data: d}; }); });
    }

    // --- per-run scan settings -------------------------------------------

    const settingsBox = document.getElementById("runSettings");
    const settingsBtn = document.getElementById("settingsBtn");
    const cfg = {
        scan_type: document.getElementById("cfgScanType"),
        engine: document.getElementById("cfgEngine"),
        discovery: document.getElementById("cfgDiscovery"),
        tcp_ports: document.getElementById("cfgTcp"),
        udp_ports: document.getElementById("cfgUdp"),
        top_ports: document.getElementById("cfgTop"),
        quick_proto: document.getElementById("cfgQuickProto"),
        nmap_ports: document.getElementById("cfgNmapPorts"),
        rate: document.getElementById("cfgRate"),
        retries: document.getElementById("cfgRetries")
    };
    const cfgHelp = document.getElementById("cfgHelp");

    function syncSettings() {
        if (!cfg.scan_type) { return; }
        const type = cfg.scan_type.value;
        // The template marks conditional blocks with data-when (the scan type
        // they belong to). A stale data-cfg here matched nothing, which is why
        // every field showed at once regardless of scan type.
        document.querySelectorAll("#runSettings [data-when]").forEach(function (el) {
            const wanted = el.dataset.when === type;
            const engineOk = !el.dataset.engine || el.dataset.engine === cfg.engine.value;
            el.classList.toggle("hidden", !(wanted && engineOk));
        });
        if (cfgHelp && type === "full") {
            const opt = cfg.engine.options[cfg.engine.selectedIndex];
            cfgHelp.innerText = opt ? opt.dataset.note : "";
        } else if (cfgHelp) {
            cfgHelp.innerText = type === "discovery"
                ? "Finds which addresses are alive and stops there."
                : "nmap over its most common ports, with service detection.";
        }
    }

    // Collected fresh on every start, so changing the engine and pressing START
    // runs the new configuration rather than the one the task was created with.
    function currentConfig() {
        if (!cfg.scan_type) { return {}; }
        const type = cfg.scan_type.value;
        const out = {scan_type: type, discovery: cfg.discovery.value};
        if (type === "full") {
            out.engine = cfg.engine.value;
            out.tcp_ports = cfg.tcp_ports.value;
            out.udp_ports = cfg.udp_ports.value;
            out.rate = cfg.rate.value;
            out.retries = cfg.retries.value;
        } else if (type === "quick") {
            out.top_ports = cfg.top_ports.value;
            out.nmap_ports = cfg.nmap_ports.value;
            if (cfg.quick_proto) { out.quick_proto = cfg.quick_proto.value; }
        }
        return out;
    }

    if (settingsBtn) {
        settingsBtn.onclick = function () { settingsBox.classList.toggle("hidden"); };
    }
    if (cfg.scan_type) {
        cfg.scan_type.addEventListener("change", syncSettings);
        cfg.engine.addEventListener("change", syncSettings);
        syncSettings();
    }

    function start(resume) {
        const url = "/tasks/" + window.TASK.id + "/start" + (resume ? "?resume=1" : "");
        const body = resume ? {resume: true} : currentConfig();
        return fetch(url, {method: "POST",
                           headers: {"Content-Type": "application/json",
                                     "X-CSRF-Token": window.TASK.csrf},
                           body: JSON.stringify(body)})
            .then(function (r) { return r.json().then(function (d) { return {ok: r.ok, data: d}; }); })
            .then(function (res) {
                if (!res.ok) {
                    log("Could not start: " + res.data.error);
                    alertBox.className = "flash flash-error";
                    alertBox.innerText = "⚠️ " + res.data.error;
                    return;
                }
                alertBox.className = "hidden";
                // The log is no longer cleared: each run appends under its own
                // header so earlier passes over this target stay readable.
                setStatus("running");
                setResumable(false);
                if (settingsBox) { settingsBox.classList.add("hidden"); }
                if (!source) { connect(); }
            });
    }

    startBtn.onclick = function () { start(false); };
    resumeFileBtn.onclick = function () { start(true); };
    stopBtn.onclick = function () {
        post("stop").then(function (res) {
            // Trust the server's status: the scan may have finished on its own
            // between rendering the button and the click landing.
            setStatus(res.data.status);
            setResumable(res.data.resumable);
        });
    };
    pauseBtn.onclick = function () {
        post(state === "paused" ? "resume" : "pause").then(function (res) {
            setStatus(res.data.status);
        });
    };

    // --- host view toggle --------------------------------------------------

    function applyView(view) {
        const table = view !== "cards";
        if (tableView) { tableView.hidden = !table; }
        if (cardsView) { cardsView.hidden = table; }
    }
    document.querySelectorAll('input[name="hostview"]').forEach(function (radio) {
        radio.addEventListener("change", function () {
            if (!radio.checked) { return; }
            applyView(radio.value);
            try { window.localStorage.setItem("sloth.hostview", radio.value); }
            catch (err) { /* private mode — the choice just won't persist */ }
        });
    });
    try {
        const saved = window.localStorage.getItem("sloth.hostview");
        if (saved) {
            const radio = document.querySelector('input[name="hostview"][value="' + saved + '"]');
            if (radio) { radio.checked = true; }
            applyView(saved);
        }
    } catch (err) { /* ignore */ }

    // --- boot -------------------------------------------------------------

    setStatus(window.TASK.isPaused ? "paused" : window.TASK.status);
    setResumable(window.TASK.canResume);
    logBox.scrollTop = logBox.scrollHeight;   // show the tail of a restored log

    // Always connected: the stream carries rescan results as well as sweep
    // events, so it must be live even when no sweep is running.
    connect();
    if (window.TASK.autostart) { start(false); }
}());
