/* Drives a tool-task result page (shodan/archive/headers/source): autostarts the
   run if asked, then listens on the task stream and reloads when it finishes so
   the freshly-stored results render. */
(function () {
    "use strict";
    var T = window.TOOLTASK;
    if (!T) { return; }
    var dot = document.getElementById("statusDot");
    var text = document.getElementById("statusText");
    var runBtn = document.getElementById("runBtn");
    var HUE = {running: "#e0a03a", completed: "#3fb984", error: "#f2555a",
               pending: "rgba(233,233,237,.4)", interrupted: "rgba(233,233,237,.4)"};

    function setStatus(s) {
        if (text) { text.textContent = s; }
        if (dot) { dot.style.background = HUE[s] || HUE.pending; dot.classList.toggle("live", s === "running"); }
        if (runBtn) { runBtn.classList.toggle("hidden", s === "running"); }
    }

    function start() {
        setStatus("running");
        fetch("/tasks/" + T.id + "/start", {method: "POST",
            headers: {"Content-Type": "application/json", "X-CSRF-Token": T.csrf}, body: "{}"})
            .then(function (r) { return r.json().then(function (d) { return {ok: r.ok, d: d}; }); })
            .then(function (res) { if (!res.ok) { setStatus("error"); alert(res.d.error || "could not start"); } });
    }

    var source = new EventSource("/tasks/" + T.id + "/stream");
    source.onmessage = function (msg) {
        var ev = JSON.parse(msg.data);
        if (ev.type === "status" && ev.status) { setStatus(ev.status); }
        if (ev.type === "done") {
            source.close();
            location.reload();   // pull in the stored results
        }
    };
    source.onerror = function () { /* the stream stays flaky during restarts; ignore */ };

    if (runBtn) { runBtn.addEventListener("click", start); }
    setStatus(T.status);
    if (T.autostart && T.status !== "running" && T.status !== "completed") { start(); }
})();
