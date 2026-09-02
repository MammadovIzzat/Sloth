/* Live scan console.
   Renders the host list, the by-port grouping and the inspector from an embedded
   model (window.TASK.hosts / .reports), then applies SSE deltas as the sweep
   runs so a reload mid-scan never loses results. */
(function () {
    "use strict";
    var T = window.TASK;

    /* ---- service families: a JS mirror of sloth/palette.py, so a port that
       arrives live over the stream gets the same colour as a server-rendered one. */
    var FAM = {
        web:    {hue:"#8ab2f5", bg:"color-mix(in srgb,#5b8def 16%,transparent)"},
        remote: {hue:"#f0c076", bg:"color-mix(in srgb,#e0a03a 16%,transparent)"},
        data:   {hue:"#cbb0f5", bg:"color-mix(in srgb,#a67ce8 16%,transparent)"},
        file:   {hue:"#ffb4b6", bg:"color-mix(in srgb,#f2555a 16%,transparent)"},
        infra:  {hue:"#7fd8b0", bg:"color-mix(in srgb,#3fb984 16%,transparent)"},
        neutral:{hue:"rgba(233,233,237,.72)", bg:"rgba(233,233,237,.08)"}
    };
    var PORTS = {21:"file",20:"file",22:"remote",23:"remote",25:"infra",53:"infra",67:"infra",
        68:"infra",69:"file",88:"infra",110:"infra",111:"infra",123:"infra",135:"remote",137:"file",
        138:"file",139:"file",143:"infra",161:"infra",162:"infra",389:"infra",443:"web",445:"file",
        465:"infra",500:"infra",514:"infra",515:"file",587:"infra",631:"file",636:"infra",993:"infra",
        995:"infra",1433:"data",1521:"data",2049:"file",3268:"infra",3306:"data",3389:"remote",
        5060:"infra",5432:"data",5900:"remote",5901:"remote",5985:"remote",5986:"remote",6379:"data",
        8080:"web",8443:"web",8000:"web",8008:"web",9200:"data",27017:"data",11211:"data",80:"web"};
    var KW = [["http","web"],["ssl","web"],["www","web"],["ssh","remote"],["rdp","remote"],
        ["vnc","remote"],["wbt","remote"],["telnet","remote"],["winrm","remote"],["mysql","data"],
        ["postgres","data"],["mssql","data"],["oracle","data"],["mongo","data"],["redis","data"],
        ["sql","data"],["elastic","data"],["smb","file"],["microsoft-ds","file"],["netbios","file"],
        ["ftp","file"],["nfs","file"],["cifs","file"],["dns","infra"],["domain","infra"],["ldap","infra"],
        ["smtp","infra"],["imap","infra"],["pop3","infra"],["kerberos","infra"],["ntp","infra"],
        ["snmp","infra"],["sip","infra"]];
    function famFor(port, svc) {
        if (PORTS[port]) { return FAM[PORTS[port]]; }
        var s = (svc || "").toLowerCase();
        for (var i = 0; i < KW.length; i++) { if (s.indexOf(KW[i][0]) > -1) { return FAM[KW[i][1]]; } }
        return FAM.neutral;
    }

    // ---- model ----------------------------------------------------------
    var hosts = new Map();      // ip -> {ip, rdns, src, ports: Map(key -> port)}
    var reports = [];           // {ip, id, tool, created_at}
    var rescanning = new Map(); // ip -> tool
    var selected = null;
    var view = "host";
    var query = "";
    var state = T.status;
    var source = null;
    var lastTool = (T.rescanTools && T.rescanTools[0]) ? T.rescanTools[0].key : null;

    function keyOf(p) { return p.port + "/" + p.proto; }
    function ipSort(a, b) {
        var m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
        var x = m.exec(a), y = m.exec(b);
        if (x && y) {
            for (var i = 1; i <= 4; i++) { if (+x[i] !== +y[i]) { return +x[i] - +y[i]; } }
            return 0;
        }
        return a < b ? -1 : a > b ? 1 : 0;
    }
    function addHost(ip, rdns, src) {
        var h = hosts.get(ip);
        if (!h) { h = {ip: ip, rdns: rdns || "", src: src || "", ports: new Map()}; hosts.set(ip, h); }
        else { if (rdns) { h.rdns = rdns; } if (src) { h.src = src; } }
        return h;
    }
    function setPort(ip, p) {
        var h = addHost(ip);
        h.ports.set(keyOf(p), p);
        if (p.source && !h.src) { h.src = p.source; }
    }

    (T.hosts || []).forEach(function (h) {
        addHost(h.ip, h.hostname || h.rdns, h.discovered_by);
        (h.ports || []).forEach(function (p) { setPort(h.ip, p); });
    });
    (T.reports || []).forEach(function (r) {
        reports.push({ip: r.ip, id: r.id, tool: r.tool, created_at: r.created_at});
    });
    Object.keys(T.rescanning || {}).forEach(function (ip) { rescanning.set(ip, T.rescanning[ip]); });

    // ---- DOM refs -------------------------------------------------------
    var $ = function (id) { return document.getElementById(id); };
    var hostList = $("hostList"), portList = $("portList"), emptyState = $("emptyState");
    var resultSearch = $("resultSearch"), resultCount = $("resultCount");
    var segHost = $("segHost"), segPort = $("segPort");
    var logBox = $("logBox"), logDot = $("logDot");
    var statusDot = $("statusDot"), statusText = $("statusText"), phaseBadge = $("phaseBadge");
    var startBtn = $("startBtn"), pauseBtn = $("pauseBtn"), stopBtn = $("stopBtn");
    var resumeFileBtn = $("resumeFileBtn"), settingsBtn = $("settingsBtn");
    var settingsBox = $("runSettings"), progressWrap = $("progressWrap");
    var progressBar = $("progressBar"), progressLabel = $("progressLabel"), rateLabel = $("rateLabel");
    var respondedCount = $("respondedCount"), alertBox = $("networkAlertBox");
    var inspIp = $("inspIp"), inspMeta = $("inspMeta"), inspActions = $("inspActions"),
        inspPorts = $("inspPorts"), inspReports = $("inspReports"), inspReportsEmpty = $("inspReportsEmpty");

    var STATUS_HUE = {running:"#e0a03a", paused:"#9dbcf7", completed:"#3fb984",
                      stopped:"#f2555a", error:"#f2555a", interrupted:"rgba(233,233,237,.4)",
                      pending:"rgba(233,233,237,.4)"};

    // ---- rendering ------------------------------------------------------
    function log(line) { logBox.textContent += line + "\n"; logBox.scrollTop = logBox.scrollHeight; }

    function matchHost(h) {
        var q = query;
        if (!q) { return true; }
        if (h.ip.toLowerCase().indexOf(q) > -1) { return true; }
        if ((h.rdns || "").toLowerCase().indexOf(q) > -1) { return true; }
        var hit = false;
        h.ports.forEach(function (p) {
            if (String(p.port).indexOf(q) > -1 || (p.service || "").toLowerCase().indexOf(q) > -1) { hit = true; }
        });
        return hit;
    }
    function pill(p) {
        var f = famFor(p.port, p.service);
        var dim = String(p.state || "open").indexOf("open") !== 0 ? "; opacity:.6" : "";
        return '<span class="pill" style="color:' + f.hue + '; background:' + f.bg + dim + '" title="' +
            (p.state || "open") + (p.source ? " · " + p.source : "") + '">' +
            '<b>' + p.port + '</b><span class="svc">' + (p.service || p.proto) + '</span></span>';
    }

    function sortedHosts() {
        return Array.from(hosts.values()).sort(function (a, b) { return ipSort(a.ip, b.ip); });
    }

    function renderHosts() {
        var frag = document.createDocumentFragment();
        var shown = 0;
        sortedHosts().forEach(function (h) {
            if (!matchHost(h)) { return; }
            shown++;
            var ports = Array.from(h.ports.values()).sort(function (a, b) { return a.port - b.port; });
            var row = document.createElement("a");
            row.className = "lrow click" + (h.ip === selected ? " sel" : "");
            row.href = "#";
            row.dataset.ip = h.ip;
            row.innerHTML =
                '<div style="flex:none; width:112px">' +
                  '<div class="lrow-ip">' + h.ip + '</div>' +
                  '<div class="lrow-rdns">' + (h.rdns || "no reverse dns") + '</div>' +
                '</div>' +
                '<div class="lrow-ports">' + ports.map(pill).join("") +
                  (ports.length ? "" : '<span class="host-empty">host up — no open ports</span>') + '</div>' +
                '<div class="mono" style="flex:none; width:56px; text-align:right; font-size:11.5px; color:rgba(233,233,237,.45)">' +
                  (ports.length ? ports.length + " open" : "—") + '</div>' +
                '<div style="flex:none; width:64px; text-align:right; font-size:10.5px; color:rgba(233,233,237,.28)">' +
                  (h.src || "") + '</div>';
            row.addEventListener("click", function (e) { e.preventDefault(); select(h.ip); });
            frag.appendChild(row);
        });
        hostList.innerHTML = "";
        hostList.appendChild(frag);
        return shown;
    }

    function renderPortGroups() {
        var groups = new Map();   // key -> {port, proto, service, ips:[]}
        sortedHosts().forEach(function (h) {
            h.ports.forEach(function (p) {
                var k = keyOf(p);
                var g = groups.get(k);
                if (!g) { g = {port: p.port, proto: p.proto, service: p.service, ips: []}; groups.set(k, g); }
                if (!g.service && p.service) { g.service = p.service; }
                g.ips.push(h.ip);
            });
        });
        var arr = Array.from(groups.values()).sort(function (a, b) { return a.port - b.port || (a.proto < b.proto ? -1 : 1); });
        var frag = document.createDocumentFragment();
        var shown = 0;
        arr.forEach(function (g) {
            var q = query;
            if (q && String(g.port).indexOf(q) === -1 && (g.service || "").toLowerCase().indexOf(q) === -1
                && g.ips.join(" ").toLowerCase().indexOf(q) === -1) { return; }
            shown++;
            var f = famFor(g.port, g.service);
            var row = document.createElement("div");
            row.className = "lrow";
            row.style.cssText = "padding:11px 24px; gap:16px; align-items:baseline";
            row.innerHTML =
                '<div style="flex:none; width:112px">' +
                  '<div class="mono" style="font-size:13.5px; color:' + f.hue + '">' + g.port + '/' + g.proto + '</div>' +
                  '<div style="font-size:10.5px; color:rgba(233,233,237,.35); margin-top:1px">' + (g.service || "") + '</div>' +
                '</div>' +
                '<div class="mono" style="flex:1; min-width:0; display:flex; flex-wrap:wrap; gap:4px 6px; font-size:11.5px; color:rgba(233,233,237,.62)">' +
                  g.ips.map(function (ip) { return '<span data-ip="' + ip + '" style="padding:1px 5px; border-radius:3px; cursor:pointer">' + ip + '</span>'; }).join("") +
                '</div>' +
                '<div class="mono" style="flex:none; width:44px; text-align:right; font-size:12px; color:' + f.hue + '">' + g.ips.length + '</div>';
            row.querySelectorAll("[data-ip]").forEach(function (s) {
                s.addEventListener("click", function () { view = "host"; syncSeg(); select(s.dataset.ip); });
            });
            frag.appendChild(row);
        });
        portList.innerHTML = "";
        portList.appendChild(frag);
        return shown;
    }

    function reportsFor(ip) {
        return reports.filter(function (r) { return r.ip === ip; })
            .sort(function (a, b) { return (a.created_at < b.created_at) ? 1 : -1; });
    }

    function renderInspector() {
        if (!selected || !hosts.has(selected)) {
            var first = sortedHosts()[0];
            selected = first ? first.ip : null;
        }
        if (!selected) {
            inspIp.textContent = "—"; inspMeta.textContent = "no hosts yet";
            inspActions.innerHTML = ""; inspPorts.innerHTML = ""; inspReports.innerHTML = "";
            inspReportsEmpty.classList.remove("hidden");
            return;
        }
        var h = hosts.get(selected);
        var ports = Array.from(h.ports.values()).sort(function (a, b) { return a.port - b.port; });
        inspIp.textContent = h.ip;
        inspMeta.textContent = (h.rdns || "no reverse dns") + " · " + ports.length + " open" + (h.src ? " · via " + h.src : "");

        // actions: rescan tool picker + go, plus copy
        inspActions.innerHTML = "";
        var busy = rescanning.get(h.ip);
        if (busy) {
            var b = document.createElement("div");
            b.style.cssText = "flex:1; display:flex; align-items:center; justify-content:center; gap:6px; padding:6px; border-radius:5px; font-size:12px; color:#f0c076; border:1px solid color-mix(in srgb,#e0a03a 45%,transparent)";
            b.innerHTML = '<span class="dot2 live" style="background:#e0a03a"></span>' + busy.replace(/_/g, " ") + "…";
            inspActions.appendChild(b);
            var stop = document.createElement("div");
            stop.className = "cbtn cbtn-danger"; stop.style.cssText = "padding:6px 10px; cursor:pointer";
            stop.textContent = "Stop";
            stop.addEventListener("click", function () { requestStop(h.ip); });
            inspActions.appendChild(stop);
        } else {
            var sel = document.createElement("select");
            sel.className = "cinput"; sel.style.cssText = "flex:1; width:auto; padding:6px 8px; font-size:12px";
            (T.rescanTools || []).forEach(function (t) {
                var o = document.createElement("option");
                o.value = t.key; o.textContent = t.available ? t.label : t.label + " — " + t.tool + " missing";
                if (!t.available) { o.disabled = true; }
                if (t.key === lastTool) { o.selected = true; }
                sel.appendChild(o);
            });
            var go = document.createElement("div");
            go.className = "cbtn cbtn-accent"; go.style.cssText = "cursor:pointer; padding:6px 10px";
            go.innerHTML = '<i class="ph ph-crosshair"></i>Rescan';
            go.addEventListener("click", function () { lastTool = sel.value; rescan(h.ip, sel.value); });
            inspActions.appendChild(sel);
            inspActions.appendChild(go);
        }
        var copy = document.createElement("div");
        copy.className = "cbtn"; copy.style.cssText = "width:32px; justify-content:center; padding:6px 0; cursor:pointer"; copy.title = "Copy address";
        copy.innerHTML = '<i class="ph ph-copy"></i>';
        copy.addEventListener("click", function () {
            if (navigator.clipboard) { navigator.clipboard.writeText(h.ip); }
        });
        inspActions.appendChild(copy);

        // ports
        inspPorts.innerHTML = ports.map(function (p) {
            var f = famFor(p.port, p.service);
            return '<div class="insp-port" style="border-left-color:' + f.hue + '">' +
                '<span class="mono" style="font-size:12.5px; width:58px; color:' + f.hue + '">' + p.port + '/' + p.proto + '</span>' +
                '<span style="font-size:12px; color:rgba(233,233,237,.7)">' + (p.service || "—") + '</span>' +
                '<span class="mono" style="margin-left:auto; font-size:10px; color:rgba(233,233,237,.28)">' + (p.source || "") + '</span>' +
                '</div>';
        }).join("") || '<div style="padding:7px 18px" class="host-empty">no open ports</div>';

        // reports
        var rs = reportsFor(h.ip);
        inspReports.innerHTML = rs.map(function (r) {
            return '<a class="insp-report" href="/nmap-result/' + r.id + '">' +
                '<div class="mono" style="font-size:11.5px; color:var(--color-accent-300)">' + (r.tool || "nmap") + '</div>' +
                '<div style="font-size:10.5px; color:rgba(233,233,237,.32); margin-top:1px">' + (r.created_at || "") + '</div></a>';
        }).join("");
        inspReportsEmpty.classList.toggle("hidden", rs.length > 0);
    }

    function updateCounts(shown) {
        if (respondedCount) { respondedCount.textContent = hosts.size; }
        if (resultCount) {
            resultCount.textContent = view === "host"
                ? shown + (shown === 1 ? " host" : " hosts")
                : shown + (shown === 1 ? " port" : " ports");
        }
        if (emptyState) { emptyState.classList.toggle("hidden", hosts.size > 0); }
    }

    function renderNow() {
        var shown = view === "host" ? renderHosts() : renderPortGroups();
        renderInspector();
        updateCounts(shown);
    }
    var pending = false;
    // setTimeout, not requestAnimationFrame: rAF is suspended while the tab is
    // backgrounded, which would strand the first paint and live deltas.
    function scheduleRender() {
        if (pending) { return; }
        pending = true;
        setTimeout(function () { pending = false; renderNow(); }, 0);
    }
    function select(ip) { selected = ip; scheduleRender(); }

    // ---- controls / status ---------------------------------------------
    function setStatus(next) {
        state = next;
        if (statusText) { statusText.textContent = next; }
        if (statusDot) { statusDot.style.background = STATUS_HUE[next] || STATUS_HUE.pending;
            statusDot.classList.toggle("live", next === "running"); }
        var live = next === "running" || next === "paused";
        if (!live && phaseBadge) { phaseBadge.classList.add("hidden"); }
        startBtn.classList.toggle("hidden", live);
        pauseBtn.classList.toggle("hidden", !live);
        stopBtn.classList.toggle("hidden", !live);
        progressWrap.classList.toggle("hidden", !live);
        pauseBtn.innerHTML = next === "paused" ? '<i class="ph ph-play"></i>Resume' : '<i class="ph ph-pause"></i>Pause';
        startBtn.innerHTML = next === "pending" ? '<i class="ph ph-play"></i>Start' : '<i class="ph ph-play"></i>Run again';
        if (logDot) { logDot.style.background = next === "running" ? "#e0a03a"
            : (next === "error" || next === "stopped") ? "#f2555a"
            : next === "completed" ? "#3fb984" : "rgba(233,233,237,.3)"; }
    }
    function setResumable(can) {
        resumeFileBtn.classList.toggle("hidden", !can || state === "running" || state === "paused");
    }
    function setPhase(phase, label) {
        if (!phaseBadge) { return; }
        phaseBadge.textContent = (phase === "discovery" ? "🔎 discovering" : "⚡ port scan") + (label ? " · " + label : "");
        phaseBadge.classList.remove("hidden");
    }

    function post(action) {
        return fetch("/tasks/" + T.id + "/" + action, {method: "POST", headers: {"X-CSRF-Token": T.csrf}})
            .then(function (r) { return r.json().then(function (d) { return {ok: r.ok, data: d}; }); });
    }

    // ---- per-run scan settings (unchanged contract) ---------------------
    var cfg = {
        scan_type: $("cfgScanType"), engine: $("cfgEngine"), discovery: $("cfgDiscovery"),
        tcp_ports: $("cfgTcp"), udp_ports: $("cfgUdp"), top_ports: $("cfgTop"),
        quick_proto: $("cfgQuickProto"), nmap_ports: $("cfgNmapPorts"), rate: $("cfgRate"), retries: $("cfgRetries")
    };
    function syncSettings() {
        if (!cfg.scan_type) { return; }
        var type = cfg.scan_type.value;
        document.querySelectorAll("#runSettings [data-when]").forEach(function (el) {
            var wanted = el.dataset.when === type;
            var engineOk = !el.dataset.engine || el.dataset.engine === cfg.engine.value;
            el.classList.toggle("hidden", !(wanted && engineOk));
        });
    }
    function currentConfig() {
        if (!cfg.scan_type) { return {}; }
        var type = cfg.scan_type.value;
        var out = {scan_type: type, discovery: cfg.discovery.value};
        if (type === "full") {
            out.engine = cfg.engine.value; out.tcp_ports = cfg.tcp_ports.value;
            out.udp_ports = cfg.udp_ports.value; out.rate = cfg.rate.value; out.retries = cfg.retries.value;
        } else if (type === "quick") {
            out.top_ports = cfg.top_ports.value; out.nmap_ports = cfg.nmap_ports.value;
            if (cfg.quick_proto) { out.quick_proto = cfg.quick_proto.value; }
        }
        return out;
    }
    if (settingsBtn) { settingsBtn.onclick = function () { settingsBox.classList.toggle("hidden"); }; }
    if (cfg.scan_type) {
        cfg.scan_type.addEventListener("change", syncSettings);
        cfg.engine.addEventListener("change", syncSettings);
        syncSettings();
    }

    function start(resume) {
        var url = "/tasks/" + T.id + "/start" + (resume ? "?resume=1" : "");
        var body = resume ? {resume: true} : currentConfig();
        return fetch(url, {method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": T.csrf},
                           body: JSON.stringify(body)})
            .then(function (r) { return r.json().then(function (d) { return {ok: r.ok, data: d}; }); })
            .then(function (res) {
                if (!res.ok) {
                    log("Could not start: " + res.data.error);
                    alertBox.className = "flash flash-error"; alertBox.textContent = "⚠️ " + res.data.error;
                    return;
                }
                alertBox.className = "hidden";
                setStatus("running"); setResumable(false);
                if (settingsBox) { settingsBox.classList.add("hidden"); }
                if (!source) { connect(); }
            });
    }
    startBtn.onclick = function () { start(false); };
    resumeFileBtn.onclick = function () { start(true); };
    stopBtn.onclick = function () { post("stop").then(function (res) { setStatus(res.data.status); setResumable(res.data.resumable); }); };
    pauseBtn.onclick = function () { post(state === "paused" ? "resume" : "pause").then(function (res) { setStatus(res.data.status); }); };

    // ---- rescan ---------------------------------------------------------
    function rescan(ip, tool) {
        rescanning.set(ip, tool); renderInspector();
        fetch("/tasks/" + T.id + "/rescan", {method: "POST",
            headers: {"Content-Type": "application/json", "X-CSRF-Token": T.csrf},
            body: JSON.stringify({ip: ip, tool: tool})})
        .then(function (r) { return r.json().then(function (d) { return {ok: r.ok, data: d}; }); })
        .then(function (res) {
            if (!res.ok || res.data.error) { rescanning.delete(ip); renderInspector();
                log("rescan " + ip + " rejected: " + (res.data.error || "unknown error")); }
        })
        .catch(function (err) { rescanning.delete(ip); renderInspector(); log("rescan " + ip + " failed: " + err); });
    }
    function requestStop(ip) {
        fetch("/tasks/" + T.id + "/rescan/stop", {method: "POST",
            headers: {"Content-Type": "application/json", "X-CSRF-Token": T.csrf},
            body: JSON.stringify({ip: ip})})
        .then(function (r) { return r.json().then(function (d) { return {ok: r.ok, data: d}; }); })
        .then(function (res) { if (!res.ok) { log("stop " + ip + ": " + (res.data.error || "failed")); } });
    }
    function onRescanEvent(ev) {
        if (ev.state === "running") { rescanning.set(ev.ip, ev.tool); renderInspector(); return; }
        rescanning.delete(ev.ip);
        if (ev.state === "error") { log("rescan " + ev.ip + " failed: " + ev.error); renderInspector(); return; }
        if (ev.state === "cancelled") { log(ev.message || ("rescan " + ev.ip + " stopped")); renderInspector(); return; }
        if (ev.ports) {
            var h = hosts.get(ev.ip);
            if (h) { h.ports.clear(); ev.ports.forEach(function (p) { setPort(ev.ip, p); }); }
        }
        if (ev.scan_id) {
            reports.unshift({ip: ev.ip, id: ev.scan_id, tool: ev.tool, created_at: "just now"});
        }
        if (ev.note) { log(ev.ip + ": " + ev.note); }
        scheduleRender();
    }

    // ---- network banner -------------------------------------------------
    function showNetwork(ev) {
        if (ev.connected) {
            alertBox.className = "flash flash-ok";
            alertBox.innerHTML = '<div><b>🟢 Network restored</b> — reconnected at ' + (ev.reconnected_at || "") +
                '. <a id="netResume" href="#">Resume scan</a></div>';
            var r = $("netResume");
            if (r) { r.onclick = function (e) { e.preventDefault(); post("resume").then(function () { setStatus("running"); alertBox.className = "hidden"; }); }; }
        } else {
            alertBox.className = "flash flash-error";
            alertBox.innerHTML = '<div><b>🚨 Network lost — scan paused automatically.</b> The scanners are frozen, not killed — nothing is lost.</div>';
            setStatus("paused");
        }
    }

    // ---- streaming ------------------------------------------------------
    function connect() {
        if (source) { source.close(); }
        source = new EventSource("/tasks/" + T.id + "/stream");
        source.onmessage = function (msg) {
            var ev = JSON.parse(msg.data);
            switch (ev.type) {
                case "snapshot":
                    ev.hosts.forEach(function (h) {
                        addHost(h.ip, h.hostname || h.rdns, h.discovered_by);
                        (h.ports || []).forEach(function (p) { setPort(h.ip, p); });
                    });
                    scheduleRender(); break;
                case "phase": setPhase(ev.phase, ev.label || ev.tool); break;
                case "discovered": addHost(ev.ip, ev.hostname, ev.reason); scheduleRender(); break;
                case "discovery_done": log("Discovery finished: " + ev.count + " host(s) up."); setPhase("portscan", null); break;
                case "host": setPort(ev.ip, ev.port); scheduleRender(); break;
                case "progress":
                    progressBar.style.width = ev.percent + "%";
                    progressLabel.textContent = ev.percent.toFixed(2) + "% done" + (ev.remaining ? " · " + ev.remaining + " remaining" : "");
                    rateLabel.textContent = ev.rate_kpps + " kpps" + (ev.found != null ? " · found " + ev.found : "");
                    break;
                case "status": setStatus(ev.status); if (ev.message) { log(ev.message); } break;
                case "network": showNetwork(ev); break;
                case "rescan": onRescanEvent(ev); break;
                case "log": log(ev.line); break;
                case "done": setStatus(ev.status); setResumable(ev.resumable); if (ev.error) { log("Error: " + ev.error); } break;
            }
        };
        source.onerror = function () {
            if (source) { source.close(); source = null; }
            setTimeout(function () { if (!source) { connect(); } }, 3000);
        };
    }

    // ---- filter / view toggle / surface --------------------------------
    if (resultSearch) {
        resultSearch.addEventListener("input", function () { query = resultSearch.value.trim().toLowerCase(); scheduleRender(); });
    }
    function syncSeg() {
        segHost.classList.toggle("on", view === "host");
        segPort.classList.toggle("on", view === "port");
        hostList.hidden = view !== "host";
        portList.hidden = view !== "port";
    }
    if (segHost) { segHost.onclick = function () { view = "host"; syncSeg(); scheduleRender(); }; }
    if (segPort) { segPort.onclick = function () { view = "port"; syncSeg(); scheduleRender(); }; }
    document.querySelectorAll("#surfaceBand [data-filter]").forEach(function (cell) {
        cell.addEventListener("click", function () {
            if (resultSearch) { resultSearch.value = cell.dataset.filter; }
            query = String(cell.dataset.filter).toLowerCase(); scheduleRender();
        });
    });

    // ---- boot -----------------------------------------------------------
    setStatus(state);
    setResumable(T.canResume);
    renderNow();
    connect();
    if (T.autostart) { start(false); }
})();
