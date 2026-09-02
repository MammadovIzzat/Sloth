"""Task formats — the tools a task can run.

Sloth started as a port scanner and is growing into a small platform: the same
project accumulates findings from several tools. Only ``host`` (masscan → nmap)
is built; the rest are declared here so the New-task picker can show them as
"coming soon" and we can turn them on one at a time.

Each format drives the New-task page: its identity (icon/hue/blurb), the command
it will run, and — for the not-yet-built ones — the fields to preview so the
picker communicates what the tool will do.
"""

TASK_FORMATS = [
    {
        "id": "host", "name": "Host scan", "icon": "ph ph-crosshair",
        "hue": "var(--color-accent)", "engine": "masscan → nmap",
        "blurb": "Sweep an IP range for open ports, then fingerprint what answered.",
        "coming_soon": False,
    },
    {
        "id": "shodan", "name": "Shodan domain", "icon": "ph ph-globe-hemisphere-west",
        "hue": "#cbb0f5", "engine": "Shodan API",
        "blurb": "Pull everything Shodan already knows about a domain. Nothing is sent to the target.",
        "coming_soon": False, "needs_key": True,
        "key_note": "Will use your stored Shodan key — 1 credit per page of results.",
        "cmd_head": "shodan search",
        "cmd_rest": "hostname:acme.example --fields ip_str,port,org,location.country_code,product",
        "fields": [
            {"name": "target", "label": "Domain", "ph": "acme.example", "hint": "Subdomains are included automatically.", "font": "mono", "span": "span 2"},
            {"name": "max_pages", "label": "Max pages", "ph": "5", "hint": "100 results per page, 1 credit each.", "font": "mono", "span": "auto"},
            {"name": "facet", "label": "Facet", "ph": "org,port,country", "hint": "", "font": "mono", "span": "auto"},
        ],
        "opts": ["Include historical banners", "Only hosts with vulns", "Resolve subdomains first"],
    },
    {
        "id": "archive", "name": "Web archive", "icon": "ph ph-clock-counter-clockwise",
        "hue": "#8ab2f5", "engine": "Wayback CDX",
        "blurb": "Every URL the Internet Archive ever saw for a domain, including the ones since deleted.",
        "coming_soon": False,
        "cmd_head": "curl -s",
        "cmd_rest": "'https://web.archive.org/cdx/search/cdx?url=*.acme.example/*&output=txt&fl=original&collapse=urlkey'",
        "fields": [
            {"name": "target", "label": "Domain", "ph": "acme.example", "hint": "Subdomains and every path under them are included automatically.", "font": "mono", "span": "span 2"},
        ],
        "opts": [],
    },
    {
        "id": "headers", "name": "Header check", "icon": "ph ph-shield-check",
        "hue": "#f0c076", "engine": "curl -sI",
        "blurb": "Grade the security headers on every web endpoint this project knows about.",
        "coming_soon": False,
        "cmd_head": "curl -sI", "cmd_rest": "--max-time 10 --follow < endpoints.txt",
        "fields": [
            {"name": "endpoints", "label": "Endpoints", "ph": "auto — leave blank to use this project\u2019s 443/8080 hosts", "hint": "Or paste your own, one URL per line.", "font": "body", "span": "span 2", "textarea": True},
            {"name": "timeout", "label": "Timeout (s)", "ph": "10", "hint": "", "font": "mono", "span": "auto"},
            {"name": "user_agent", "label": "User agent", "ph": "sloth/{version}", "hint": "", "font": "mono", "span": "auto"},
        ],
        "opts": ["Follow redirects", "Both http and https", "Flag missing CSP as high"],
    },
    {
        "id": "source", "name": "Source enum", "icon": "ph ph-code",
        "hue": "#7fd8b0", "engine": "crawler + regex",
        "blurb": "Crawl a URL and grep every asset it serves for patterns you define.",
        "coming_soon": True,
        "cmd_head": "sloth-src", "cmd_rest": "https://acme.example --depth 2 --rules secrets,endpoints",
        "fields": [
            {"name": "target", "label": "Start URL", "ph": "https://acme.example", "hint": "", "font": "mono", "span": "span 2"},
            {"name": "depth", "label": "Crawl depth", "ph": "2", "hint": "Depth 3+ gets slow on large sites.", "font": "mono", "span": "auto"},
            {"name": "rules", "label": "Rule set", "ph": "secrets, endpoints", "hint": "Or write your own regex below.", "font": "body", "span": "auto"},
            {"name": "regex", "label": "Custom regex", "ph": "", "hint": "PCRE. Optional \u2014 adds to the rule set above.", "font": "mono", "span": "span 2"},
        ],
        "opts": ["Inline scripts", "External .js", "Source maps", "Comments only"],
    },
]

FORMAT_BY_ID = {f["id"]: f for f in TASK_FORMATS}
