/* Modal dialogs.
   The design moves the create/settings forms into modals. Anything with
   data-dialog-open="<id>" opens that dialog; the backdrop, any [data-dialog-close]
   inside it, and Escape all close it. Kept deliberately small — these are plain
   forms that post normally, so there is no state to manage beyond visibility. */
(function () {
    "use strict";

    function open(id) {
        const dlg = document.getElementById(id);
        if (!dlg) { return; }
        dlg.classList.remove("hidden");
        const first = dlg.querySelector("input:not([type=hidden]), select, textarea");
        if (first) { first.focus(); }
    }

    function close(dlg) {
        if (dlg) { dlg.classList.add("hidden"); }
    }

    function closeAll() {
        document.querySelectorAll(".dialog-backdrop:not(.hidden)").forEach(close);
    }

    document.addEventListener("click", function (ev) {
        const opener = ev.target.closest("[data-dialog-open]");
        if (opener) {
            ev.preventDefault();
            open(opener.dataset.dialogOpen);
            return;
        }
        if (ev.target.closest("[data-dialog-close]")) {
            ev.preventDefault();
            close(ev.target.closest(".dialog-backdrop"));
            return;
        }
        // A click on the backdrop itself — not on the dialog inside it — closes.
        if (ev.target.classList.contains("dialog-backdrop")) { close(ev.target); }
    });

    document.addEventListener("keydown", function (ev) {
        if (ev.key === "Escape") { closeAll(); }
    });

    // Server-side validation sends you back with a flash; reopen the dialog that
    // was being filled in so the work isn't lost behind a closed modal.
    const reopen = new URLSearchParams(window.location.search).get("dialog");
    if (reopen) { open(reopen); }
}());
