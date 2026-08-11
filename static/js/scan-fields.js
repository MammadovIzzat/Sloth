/* Scan-configuration forms.
   Shows only the fields the selected scan type and engine actually use, and
   surfaces the trade-off each choice carries. The same markup appears in the
   "New scan task" dialog and in the task page's settings panel, so one script
   drives both — anything with [data-scan-form]. */
(function () {
    "use strict";

    const TYPE_HELP = {
        full: "Every selected port, via the engine you pick. Thorough and loud — "
            + "pair it with host discovery to skip dead addresses.",
        quick: "nmap against its most common ports only, with service detection. "
             + "No masscan, far less traffic.",
        discovery: "Find which addresses are alive and stop there. Use the results "
                 + "to plan a narrower scan."
    };

    function wire(form) {
        const type = form.querySelector("[data-scan-type]");
        const engine = form.querySelector("[data-scan-engine]");
        const discovery = form.querySelector("[data-scan-discovery]");
        if (!type) { return; }

        function sync() {
            const value = type.value;
            const engineValue = engine ? engine.value : null;

            form.querySelectorAll("[data-when]").forEach(function (el) {
                const matchesType = el.dataset.when === value;
                // A block can also be engine-specific — rate and retries only
                // mean anything for masscan.
                const matchesEngine = !el.dataset.engine || el.dataset.engine === engineValue;
                el.classList.toggle("hidden", !(matchesType && matchesEngine));
            });

            const typeHelp = form.querySelector("[data-type-help]");
            if (typeHelp) { typeHelp.textContent = TYPE_HELP[value] || ""; }

            // A discovery-only task has to have a method selected.
            if (discovery) {
                const none = discovery.querySelector('option[value=""]');
                if (none) {
                    none.disabled = value === "discovery";
                    if (value === "discovery" && discovery.value === "") {
                        discovery.selectedIndex = 1;
                    }
                }
            }
            syncNotes();
        }

        function syncNotes() {
            const engineHelp = form.querySelector("[data-engine-help]");
            if (engineHelp && engine) {
                const opt = engine.options[engine.selectedIndex];
                engineHelp.textContent = opt ? (opt.dataset.note || "") : "";
            }
            const discHelp = form.querySelector("[data-discovery-help]");
            if (discHelp && discovery) {
                const opt = discovery.options[discovery.selectedIndex];
                if (!opt || !opt.value) {
                    discHelp.textContent = "Every address in the range gets port-scanned, "
                        + "including the ones that aren't there. Fine for a single host.";
                } else {
                    let text = opt.dataset.tool + " — " + (opt.dataset.note || "");
                    if (opt.dataset.local === "1") {
                        text += " Only works if the target is on your own network segment.";
                    }
                    discHelp.textContent = text;
                }
            }
        }

        type.addEventListener("change", sync);
        if (engine) { engine.addEventListener("change", sync); }
        if (discovery) { discovery.addEventListener("change", syncNotes); }
        sync();
    }

    document.querySelectorAll("[data-scan-form]").forEach(wire);
}());
