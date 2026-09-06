/* Drives a tool-task result page (shodan/archive/headers/source/dirsearch):
   autostarts if asked, streams the live log, and handles Stop / edit-options /
   re-run. Reloads when the run finishes so the stored results render. */
(function () {
    "use strict";
    var T = window.TOOLTASK;
    if (!T) { return; }
    var dot = document.getElementById("statusDot");
    var text = document.getElementById("statusText");
    var runBtn = document.getElementById("runBtn");
    var stopBtn = document.getElementById("stopBtn");
    var optBtn = document.getElementById("optBtn");
    var optForm = document.getElementById("optForm");
    var optRun = document.getElementById("optRun");
    var logEl = document.getElementById("toolLog");
    var HUE = {running: "#e0a03a", completed: "#3fb984", error: "#f2555a",
               stopped: "#f2555a", pending: "rgba(233,233,237,.4)", interrupted: "rgba(233,233,237,.4)"};

    function setStatus(s) {
        if (text) { text.textContent = s; }
        if (dot) { dot.style.background = HUE[s] || HUE.pending; dot.classList.toggle("live", s === "running"); }
        var running = s === "running";
        if (runBtn) { runBtn.classList.toggle("hidden", running); }
        if (stopBtn) { stopBtn.classList.toggle("hidden", !running); }
    }

    function appendLog(line) {
        if (!logEl) { return; }
        var atBottom = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 4;
        logEl.textContent += line + "\n";
        if (atBottom) { logEl.scrollTop = logEl.scrollHeight; }
    }
    if (logEl) { logEl.scrollTop = logEl.scrollHeight; }

    function collectParams() {
        var p = {};
        document.querySelectorAll("#optForm [data-opt]").forEach(function (el) { p[el.dataset.opt] = el.value; });
        return p;
    }

    function start(params) {
        setStatus("running");
        if (logEl) { logEl.textContent = ""; }   // a fresh run starts a fresh log
        var body = params ? JSON.stringify({params: params}) : "{}";
        fetch("/tasks/" + T.id + "/start", {method: "POST",
            headers: {"Content-Type": "application/json", "X-CSRF-Token": T.csrf}, body: body})
            .then(function (r) { return r.json().then(function (d) { return {ok: r.ok, d: d}; }); })
            .then(function (res) { if (!res.ok) { setStatus("error"); alert(res.d.error || "could not start"); } });
    }

    function stop() {
        if (stopBtn) { stopBtn.disabled = true; stopBtn.textContent = "Stopping…"; }
        fetch("/tasks/" + T.id + "/stop", {method: "POST", headers: {"X-CSRF-Token": T.csrf}});
    }

    var source = new EventSource("/tasks/" + T.id + "/stream");
    source.onmessage = function (msg) {
        var ev = JSON.parse(msg.data);
        if (ev.type === "log") { appendLog(ev.line); }
        if (ev.type === "status" && ev.status) { setStatus(ev.status); }
        if (ev.type === "done") { source.close(); location.reload(); }
    };
    source.onerror = function () { /* flaky during restarts; the browser retries */ };

    if (runBtn) { runBtn.addEventListener("click", function () { start(null); }); }
    if (stopBtn) { stopBtn.addEventListener("click", stop); }
    if (optBtn && optForm) { optBtn.addEventListener("click", function () { optForm.classList.toggle("hidden"); }); }
    if (optRun) { optRun.addEventListener("click", function () { if (optForm) { optForm.classList.add("hidden"); } start(collectParams()); }); }

    setStatus(T.status);
    if (T.autostart && T.status !== "running" && T.status !== "completed") { start(null); }
})();
