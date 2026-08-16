/* Live notification toasts and the sidebar unread badge.
 *
 * A single global SSE stream (not the per-task scan stream): a toast should
 * reach you whatever page you are on. The entry is already in the database
 * before this fires, so dismissing a toast only hides it — the log keeps it. */
(function () {
    "use strict";
    var host = document.getElementById("toasts");
    var badge = document.getElementById("notifyBadge");
    if (!host) { return; }

    var ICON = {good: "check-circle", warn: "warning-circle", bad: "x-circle", info: "info"};
    var KIND = {good: "ok", warn: "error", bad: "error", info: "ok"};

    function setBadge(n) {
        if (!badge) { return; }
        badge.innerText = n > 99 ? "99+" : String(n);
        badge.classList.toggle("hidden", !n);
    }

    function toast(row) {
        var node = document.createElement("div");
        node.className = "flash flash-" + (KIND[row.level] || "ok") + " toast";

        var icon = document.createElement("i");
        icon.className = "ph ph-" + (ICON[row.level] || "info");
        node.appendChild(icon);

        var text = document.createElement("span");
        text.className = "toast-text";
        var strong = document.createElement("b");
        strong.innerText = row.title;
        text.appendChild(strong);
        if (row.message) { text.appendChild(document.createTextNode(" " + row.message)); }
        node.appendChild(text);

        var close = document.createElement("a");
        close.className = "flash-close";
        close.href = "#";
        close.innerHTML = '<i class="ph ph-x"></i>';
        close.onclick = function (e) { e.preventDefault(); node.remove(); };
        node.appendChild(close);

        if (row.task_id) {
            node.style.cursor = "pointer";
            node.addEventListener("click", function () {
                window.location = "/tasks/" + row.task_id;
            });
        }
        host.appendChild(node);
        // Failures stay until dismissed; the rest clear themselves.
        if (row.level !== "bad") { setTimeout(function () { node.remove(); }, 9000); }
        while (host.children.length > 4) { host.removeChild(host.firstChild); }
    }

    var es = new EventSource("/notifications/stream");
    es.onmessage = function (ev) {
        var data;
        try { data = JSON.parse(ev.data); } catch (e) { return; }
        if (data.type === "count") {
            setBadge(data.unseen);
        } else if (data.type === "notification") {
            setBadge(data.unseen);
            // Don't toast on the log page itself — you're already reading them.
            if (!/^\/notifications\b/.test(window.location.pathname)) {
                toast(data.notification);
            }
        }
    };
})();
