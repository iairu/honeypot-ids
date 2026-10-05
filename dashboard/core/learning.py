"""Teaching content for the Learn page and the dashboard's in-app hints.

The dashboard's audience includes cybersecurity students who have never run
a honeypot or a SIEM before. Everything here is plain data (no Qt), so it is
unit-testable and reusable by any page:

  - GLOSSARY: the terms a student meets on the pages, each with a plain
    definition and what it means in THIS project.
  - PAGE_GUIDES: one per sidebar page -- what it is for, what to try, what
    to notice. Drives sidebar tooltips, F1 help and the Learn page's tour.
  - EXPLOIT_LESSONS: one per core/exploits.EXPLOIT_PRESETS entry, keyed by
    its ``cve`` -- attack class, OWASP Top 10 (2021) category, MITRE ATT&CK
    technique, how the attack works and how to defend against it. The test
    suite checks every preset has one, so a new preset can't ship without.
  - LABS: short guided exercises that walk through the pages in order, with
    per-step progress persisted in AppState.learn_completed_steps.
  - explain_event(): a plain-language explanation for a threat-analyzer
    event (core/threat_log_parser.ThreatEvent label), for card tooltips.
"""
from __future__ import annotations

from dataclasses import dataclass


# ---- glossary ----

@dataclass(frozen=True)
class GlossaryTerm:
    term: str
    definition: str
    in_this_project: str
    page: str = ""  # sidebar page id where the concept is visible, if any


GLOSSARY: list[GlossaryTerm] = [
    GlossaryTerm(
        "Honeypot",
        "A decoy system that looks like a real target but exists only to be attacked. "
        "Nobody legitimate should use it, so any activity on it is suspicious by "
        "definition, and attackers' tools and techniques can be studied safely.",
        "The honeypot is a decoy copy of the WordPress/WooCommerce eshop with its own "
        "decoy database. Suspicious visitors are silently routed to it instead of the "
        "real shop, so they keep attacking without reaching real data.",
        "exploits",
    ),
    GlossaryTerm(
        "IDS (Intrusion Detection System)",
        "Software that watches traffic or hosts for signs of attack and raises alerts. "
        "An IDS only detects; an IPS (Intrusion Prevention System) also blocks.",
        "Two layers detect attacks here: the Lua threat analyzer in the reverse proxy "
        "(application layer, per HTTP request) and Suricata (network layer). Instead of "
        "blocking, the project deceives: detected attackers are diverted to the honeypot.",
        "exploits",
    ),
    GlossaryTerm(
        "Reverse proxy",
        "A server that sits in front of web applications, receives every client request "
        "and forwards it to a backend. It is a natural place to inspect, log and route "
        "traffic.",
        "OpenResty (nginx + Lua) is the only entry point. It scores every request and "
        "decides whether it goes to production or to a honeypot pool.",
        "health",
    ),
    GlossaryTerm(
        "Threat score",
        "A number summarising how suspicious a request or session looks, built by adding "
        "up points for individual signals (bad patterns, suspicious headers, known "
        "exploits, bad IP reputation, automation tools and so on).",
        "Scores run from 0 to 100. A session whose score reaches the honeypot threshold "
        "(80 by default) is routed to the honeypot. The Exploits page shows each signal "
        "with the points it added.",
        "exploits",
    ),
    GlossaryTerm(
        "Threat score decay",
        "Letting old evidence count for less over time, so a single mistake by a normal "
        "user doesn't mark them as an attacker forever.",
        "A session's peak score halves every SCORE_DECAY_HALF_LIFE_SECONDS (300 s by "
        "default); repeat offenders decay more slowly. Setting THREAT_DECAY_ENABLED=false "
        "in the edge .env turns decay off so scores persist. Kibana's Threat Decisions & "
        "Decay dashboard plots each request's own score against what it carried over.",
        "settings",
    ),
    GlossaryTerm(
        "Sticky session",
        "Keeping a client on the same backend for the rest of its session, usually via a "
        "cookie.",
        "Once a session is sent to a honeypot it stays bound there, so an attacker never "
        "notices the switch by suddenly landing back on the real shop.",
        "exploits",
    ),
    GlossaryTerm(
        "CVE",
        "Common Vulnerabilities and Exposures: a public ID (like CVE-2024-27956) for one "
        "specific, disclosed vulnerability in one product.",
        "The proxy knows the request patterns of a set of real WordPress plugin CVEs. A "
        "matching request goes to the honeypot immediately. Each Exploits preset fires one "
        "of them (the GENERIC-WP-* ones are common WordPress attacks without a CVE).",
        "exploits",
    ),
    GlossaryTerm(
        "Severity (CVSS)",
        "How bad a vulnerability is, usually rated with the Common Vulnerability Scoring "
        "System (0-10) and grouped as LOW, MEDIUM, HIGH or CRITICAL.",
        "Each exploit preset carries a severity label. CRITICAL ones typically allow "
        "remote code execution or full database access without logging in.",
        "exploits",
    ),
    GlossaryTerm(
        "SQL injection (SQLi)",
        "Smuggling SQL syntax into a parameter that the application pastes into a "
        "database query, so the attacker's SQL runs with the application's privileges.",
        "Several presets send a UNION SELECT payload that would dump WordPress user "
        "hashes on a vulnerable plugin. The proxy recognises the pattern and diverts it.",
        "exploits",
    ),
    GlossaryTerm(
        "Path traversal",
        "Using ../ sequences in a file path parameter to escape the intended directory "
        "and read or write arbitrary files, such as /etc/passwd.",
        "Two presets try to read /etc/passwd through a plugin's file[path] parameter.",
        "exploits",
    ),
    GlossaryTerm(
        "Remote code execution (RCE)",
        "The worst class of bug: the attacker can make the server run commands or code "
        "of their choice.",
        "The Bricks Builder and file-upload presets demonstrate RCE attempts; on the "
        "honeypot they execute nothing real.",
        "exploits",
    ),
    GlossaryTerm(
        "Web shell",
        "A small script (for example shell.php) uploaded to a web server that gives the "
        "attacker a command prompt through HTTP requests.",
        "The upload-bypass presets try to upload shell.php; the proxy's upload analysis "
        "scores that as suspicious.",
        "exploits",
    ),
    GlossaryTerm(
        "Honeytoken",
        "Fake data (a credential, an API key, a user record) planted where only an "
        "intruder would find it. Any use of it is a high-confidence alert.",
        "Honeytokens are planted in the decoy content; a request that carries one is "
        "logged as a security event and shows under Honeytoken Hits on Kibana's Attack "
        "Patterns dashboard.",
        "kibana",
    ),
    GlossaryTerm(
        "IP reputation",
        "A score for how likely an IP address is to be malicious, from past behaviour or "
        "threat-intelligence feeds such as AbuseIPDB.",
        "Suricata alerts and past honeypot hits raise an IP's reputation score (stored "
        "in Redis). A bad reputation alone can send a request to the honeypot.",
        "redis",
    ),
    GlossaryTerm(
        "Suricata",
        "An open-source network IDS that inspects packets against signature rules.",
        "Runs next to the proxy, and its alerts feed both the SIEM and the IP reputation "
        "signal.",
        "health",
    ),
    GlossaryTerm(
        "SIEM",
        "Security Information and Event Management: a system that collects logs from "
        "everywhere, stores them centrally, and lets analysts search, correlate and "
        "visualise them.",
        "The siem project: Vector ships logs into Elasticsearch, Kibana visualises them. "
        "Open it from the Kibana page.",
        "kibana",
    ),
    GlossaryTerm(
        "Elasticsearch / Kibana / Vector",
        "Elasticsearch is a search engine used as a log store, Kibana is its web UI for "
        "dashboards and searching, and Vector is a log shipper that collects and "
        "transforms logs before storing them.",
        "Together they form the SIEM stack in siem/. The Kibana page embeds its "
        "dashboards and logs you in automatically.",
        "kibana",
    ),
    GlossaryTerm(
        "Session store (Redis)",
        "Redis is a fast in-memory key-value database, often used for sessions and "
        "counters.",
        "Holds sessions, their scores and pool assignments, and IP reputation. The Redis "
        "page lets you look inside.",
        "redis",
    ),
    GlossaryTerm(
        "Automation / bot detection",
        "Recognising scripted clients (scanners, curl, sqlmap, headless browsers) by "
        "their User-Agent, headers and request rate.",
        "Sending an exploit with curl adds an automation signal on top of the exploit "
        "itself, which is why curl runs often score higher than the same path in the "
        "browser.",
        "exploits",
    ),
    GlossaryTerm(
        "Attacker sophistication",
        "Classifying attackers by skill: from scripted mass scanners up to careful, "
        "manual, targeted attackers.",
        "The proxy's sophistication analyzer classifies each session; Kibana's Session "
        "Analysis dashboard charts the results.",
        "kibana",
    ),
    GlossaryTerm(
        "False positive / false negative",
        "A false positive flags a legitimate user as an attacker; a false negative lets "
        "an attacker through unflagged. Every detection threshold trades one for the "
        "other.",
        "The honeypot threshold (honeypot_threshold in the proxy's init.lua) was raised "
        "from 50 to 80 to cut false positives. Try the Manual request tab to see which "
        "harmless-looking requests still score.",
        "exploits",
    ),
    GlossaryTerm(
        "MITRE ATT&CK",
        "A public knowledge base of real-world attacker tactics and techniques, each with "
        "an ID like T1190 (Exploit Public-Facing Application).",
        "Each exploit lesson on the Learn page names the ATT&CK technique it belongs to.",
        "learn",
    ),
    GlossaryTerm(
        "OWASP Top 10",
        "The Open Worldwide Application Security Project's list of the ten most critical "
        "web application risk categories (the 2021 edition is used here).",
        "Each exploit lesson names its OWASP Top 10 category, such as A03 Injection.",
        "learn",
    ),
    GlossaryTerm(
        "TLS certificate",
        "Proves a server's identity and enables HTTPS encryption. Self-signed "
        "certificates encrypt but aren't trusted by browsers by default.",
        "The Certificates page generates the self-signed certificates the proxy and SIEM "
        "use, which is why curl runs with -k.",
        "certificates",
    ),
]


def search_glossary(query: str) -> list[GlossaryTerm]:
    """Terms whose name or text contains every word of ``query`` (case-
    insensitive), term-name matches first. An empty query returns all."""
    words = query.lower().split()
    if not words:
        return list(GLOSSARY)
    hits = [t for t in GLOSSARY
            if all(w in f"{t.term} {t.definition} {t.in_this_project}".lower() for w in words)]
    return sorted(hits, key=lambda t: not all(w in t.term.lower() for w in words))


# ---- page guides ----

@dataclass(frozen=True)
class PageGuide:
    summary: str        # one line: what the page is for (sidebar tooltip)
    try_this: str       # a first thing to do there
    notice: str         # what a student should look for / learn from it


PAGE_GUIDES: dict[str, PageGuide] = {
    "services": PageGuide(
        "Start, stop and watch the logs of both stacks (IDS and SIEM).",
        "Press Start on the ids project, then on siem, and watch the logs scroll.",
        "Every container is a separate service: proxy, eshops, databases, Suricata, "
        "Redis. The combined log is what a sysadmin reads first when something breaks. "
        "The Honeypot layer dropdown picks where the deception happens: at the reverse "
        "proxy (separate honeypot eshops) or at the database (one eshop that switches "
        "databases per request, which cannot contain file or code-execution attacks).",
    ),
    "health": PageGuide(
        "Live diagram of every container and whether it is healthy.",
        "Stop one container from a terminal and watch its node change colour.",
        "The diagram is the system's architecture: traffic enters at the proxy, fans "
        "out to production or honeypot eshops, and everything reports to the SIEM.",
    ),
    "resources": PageGuide(
        "CPU, memory and network graphs per container.",
        "Run an exploit on the Exploits page and look for its marker on the graphs.",
        "Attacks cost resources. Scanners and brute force show up as load spikes, which "
        "is also how denial-of-service is noticed.",
    ),
    "certificates": PageGuide(
        "Generate the TLS certificates the stacks use for HTTPS.",
        "Generate certificates once before the first start.",
        "The certificates are self-signed, so browsers and curl need to be told to "
        "trust them (curl -k).",
    ),
    "redis": PageGuide(
        "Look inside the session store: sessions, threat scores, IP reputation.",
        "Run an exploit, then refresh here and find your session and its score.",
        "The proxy's memory is data you can inspect: a score is just a number in a key, "
        "and a sticky honeypot binding is just a stored pool name.",
    ),
    "backups": PageGuide(
        "Back up and restore the stacks' data volumes.",
        "Take a backup before experimenting so you can roll back.",
        "Backups are part of incident response: being able to restore a known-good "
        "state matters as much as detecting the attack.",
    ),
    "kibana": PageGuide(
        "The SIEM's dashboards: every request, alert and security event.",
        "Open Attack Patterns after running a few exploits and find your CVEs, then open "
        "Threat Decisions & Decay to see why each request was diverted.",
        "This is the analyst's view. The same attack you fired appears here as "
        "structured events you can filter, count and correlate.",
    ),
    "exploits": PageGuide(
        "Fire real WordPress exploits at the proxy and see how it reacts.",
        "Pick a preset, press 'What is this?' to read about it, then Run exploit (curl).",
        "Each card on the Threat analyzer tab is one signal that added points. Watch the "
        "score cross the threshold and the route flip to HONEYPOT.",
    ),
    "log_search": PageGuide(
        "Search raw logs across all containers.",
        "Search for the CVE ID of an exploit you just ran.",
        "Raw logs are the ground truth behind every dashboard. Being able to grep them "
        "is a core analyst skill.",
    ),
    "pool_test": PageGuide(
        "Three browsers, three separate attacker sessions, against the honeypot pool.",
        "Press Open shop in all, then Attack from all, then Refresh pool state.",
        "Attackers are told apart by session, not by address: each frame has its own cookie "
        "and browser fingerprint, so each is diverted to a honeypot pool of its own.",
    ),
    "extras": PageGuide(
        "PDF exports: implementation chapter, architecture, exploit matrix.",
        "Export the Exploit / CVE matrix as a study sheet.",
        "The matrix lists every preset with its CVE and severity in one table.",
    ),
    "settings": PageGuide(
        "Local or remote (SSH) targets, .env values, theme and polling.",
        "Open the edge .env and find SCORE_DECAY_HALF_LIFE_SECONDS and THREAT_DECAY_ENABLED.",
        "Detection is configuration: changing how fast evidence fades changes who still "
        "counts as an attacker. Change it and re-run the same exploit.",
    ),
    "learn": PageGuide(
        "Glossary, guided labs and a lesson for every exploit preset.",
        "Start with Lab 1 on the Guided labs tab.",
        "Everything on the other pages is explained here in plain language.",
    ),
}


# ---- exploit lessons ----

@dataclass(frozen=True)
class ExploitLesson:
    attack_class: str
    owasp: str       # OWASP Top 10 (2021) category
    attack: str      # MITRE ATT&CK technique, "Txxxx Name"
    how_it_works: str
    defence: str


_T1190 = "T1190 Exploit Public-Facing Application"
_SQLI_HOW = ("The plugin copies the parameter straight into an SQL query. The payload closes "
             "the original string with an apostrophe and appends UNION SELECT user_login, "
             "user_pass FROM wp_users, so the page would print usernames and password hashes.")
_SQLI_DEFENCE = ("Use prepared statements ($wpdb->prepare), validate the parameter's type "
                 "(an ID should be an integer), and update the plugin.")

EXPLOIT_LESSONS: dict[str, ExploitLesson] = {
    "CVE-2023-28121": ExploitLesson(
        "Authentication bypass", "A07 Identification and Authentication Failures", _T1190,
        "WooCommerce Payments trusted a request header to say which user was logged in. "
        "Sending X-WCPAY-PLATFORM-CHECKOUT-USER: 1 makes the site treat the request as "
        "user 1, normally the administrator.",
        "Never derive identity from a client-controlled header; update the plugin "
        "(fixed in 5.6.2)."),
    "CVE-2023-2986": ExploitLesson(
        "Hard-coded cryptographic key", "A02 Cryptographic Failures", _T1190,
        "Abandoned Cart Lite signs its checkout links with a key that is the same on every "
        "install, so anyone can forge a link that logs them in as a customer.",
        "Generate secrets per install, verify signatures server-side, update the plugin."),
    "CVE-2025-4403": ExploitLesson(
        "Unrestricted file upload", "A04 Insecure Design", "T1505.003 Web Shell",
        "The upload handler checks the file type loosely, so a PHP file (shell.php) can be "
        "uploaded and then requested to run commands on the server.",
        "Allow-list extensions and MIME types, store uploads outside the web root, and "
        "never let the web server execute files in upload folders."),
    "CVE-2025-2266": ExploitLesson(
        "Missing authorization", "A01 Broken Access Control", _T1190,
        "An AJAX action updates WordPress options without checking who is asking. Setting "
        "default_role=administrator makes every new registration an admin.",
        "Check capabilities (current_user_can) and nonces on every state-changing action."),
    "CVE-2025-47577": ExploitLesson(
        "Unrestricted file upload leading to RCE", "A04 Insecure Design", "T1505.003 Web Shell",
        "The gift voucher preview handler accepts an unauthenticated attachment upload, so "
        "a PHP file can be dropped on the server and executed.",
        "Require authentication, allow-list file types, disable PHP execution in uploads."),
    "CVE-2024-2387": ExploitLesson(
        "SQL injection", "A03 Injection", _T1190, _SQLI_HOW, _SQLI_DEFENCE),
    "CVE-2025-10142": ExploitLesson(
        "Path traversal", "A01 Broken Access Control", "T1083 File and Directory Discovery",
        "The callback builds a file path from file[path]. ../../../../etc/passwd walks up "
        "out of the uploads folder to read a system file.",
        "Resolve the real path and reject anything outside the allowed directory; never "
        "build file paths from raw user input."),
    "CVE-2024-50508": ExploitLesson(
        "Path traversal", "A01 Broken Access Control", "T1083 File and Directory Discovery",
        "Same idea as the PagSeguro bug: ../ sequences in file[path] escape the intended "
        "upload directory, allowing arbitrary file reads or writes.",
        "Canonicalise paths and compare against an allowed base directory; update the plugin."),
    "GENERIC-WP-001": ExploitLesson(
        "Sensitive file disclosure", "A05 Security Misconfiguration",
        "T1552.001 Credentials In Files",
        "wp-config.php holds the database password and secret keys. If the server ever "
        "serves it as text (a misconfiguration or a backup copy like wp-config.php.bak), "
        "the attacker owns the database.",
        "Make sure PHP files are never served as plain text, keep backups out of the web "
        "root, and deny direct access to wp-config.php."),
    "GENERIC-WP-002": ExploitLesson(
        "Exposed installer", "A05 Security Misconfiguration", _T1190,
        "install.php is only meant for first setup. On a half-installed site an attacker "
        "can finish the installation with their own admin account and database.",
        "Finish installation immediately and block installer scripts once done."),
    "GENERIC-WP-003": ExploitLesson(
        "User enumeration", "A01 Broken Access Control",
        "T1589.003 Gather Victim Identity Information: Employee Names",
        "/?author=1 redirects to /author/<username>/, revealing a valid login name. Walking "
        "1, 2, 3... lists every user, halving the work of a password-guessing attack.",
        "Block ?author= redirects for anonymous users and use login names that differ "
        "from display names."),
    "GENERIC-WP-004": ExploitLesson(
        "Brute-force amplification", "A07 Identification and Authentication Failures",
        "T1110 Brute Force",
        "xmlrpc.php's system.multicall lets one HTTP request try hundreds of passwords, "
        "slipping past login rate limits. system.listMethods (this preset) is the usual "
        "first probe.",
        "Disable XML-RPC if unused, or rate-limit it and block system.multicall."),
    "CVE-2017-1001000": ExploitLesson(
        "Content injection (defacement)", "A01 Broken Access Control", _T1190,
        "WordPress 4.7.0 and 4.7.1 checked permissions against the post id before casting it "
        "to an integer, so posts/1?id=1abc passed the check as a different, unprotected id "
        "while still editing post 1. Anyone could rewrite pages and posts.",
        "Update WordPress (fixed in 4.7.2) and monitor for unexpected content changes."),
    "GENERIC-XSS-001": ExploitLesson(
        "Cross-site scripting (script tag)", "A03 Injection", "T1189 Drive-by Compromise",
        "A <script> tag sent in the search parameter. If the page prints the search term "
        "without escaping it, the script runs in every visitor's browser who opens the link.",
        "Escape output (esc_html, esc_attr), set a Content-Security-Policy, and filter or "
        "block script tags in requests."),
    "GENERIC-XSS-002": ExploitLesson(
        "Cross-site scripting (event handler)", "A03 Injection", "T1189 Drive-by Compromise",
        "XSS without a script tag: an <img> with a broken src whose onerror handler runs "
        "JavaScript. Filters that only look for <script> miss it.",
        "Escape output by context, use a strict Content-Security-Policy, and match on "
        "handlers such as onerror= and onload=, not only on <script>."),
    "GENERIC-SQLI-001": ExploitLesson(
        "SQL injection (boolean)", "A03 Injection", _T1190,
        "A quote and OR '1'='1 in a form field. If the value is pasted into an SQL query, "
        "the condition is always true and the query returns rows it should not.",
        "Use prepared statements ($wpdb->prepare) and validate input types."),
    "GENERIC-SQLI-002": ExploitLesson(
        "SQL injection (time-based blind)", "A03 Injection", _T1190,
        "No data is returned, so the attacker asks the database to SLEEP and measures how "
        "long the response takes. A delay proves the query ran, and bits of data can then "
        "be read one at a time.",
        "Use prepared statements, and alert on SLEEP/BENCHMARK in requests and on slow queries."),
    "GENERIC-SQLI-003": ExploitLesson(
        "SQL injection (form body)", "A03 Injection", _T1190,
        "The payload is in the POST body of a form, not the URL. Filters that only inspect "
        "the URL and headers never see it, so this tests whether a body-borne attack is "
        "detected at all.",
        "Inspect request bodies too (a WAF), and use prepared statements so injection "
        "fails regardless of detection."),
    "GENERIC-ENUM-001": ExploitLesson(
        "Content discovery (wordlist scan)", "A05 Security Misconfiguration",
        "T1595.003 Active Scanning: Wordlist Scanning",
        "A tool tries a long list of common paths (/admin, /.env, /backup.zip, ...) and "
        "notes which exist. Each single request looks harmless, so the signal is the "
        "pattern across requests.",
        "Remove backups and config files from the web root, rate-limit 404 bursts, and "
        "flag clients that probe many sensitive paths."),
    "GENERIC-ENUM-002": ExploitLesson(
        "Plugin and theme discovery", "A06 Vulnerable and Outdated Components",
        "T1595.002 Active Scanning: Vulnerability Scanning",
        "Requesting each plugin's readme.txt and each theme's style.css reveals which are "
        "installed and their versions, which the attacker then matches against known CVEs.",
        "Block direct access to readme files, keep components updated, and hide version "
        "strings."),
    "GENERIC-IDOR-001": ExploitLesson(
        "Insecure direct object reference (users)", "A01 Broken Access Control",
        "T1087 Account Discovery",
        "Changing the id in /wp-json/wp/v2/users/<id> lists accounts one by one. The server "
        "answers without checking whether the requester may see them.",
        "Require authentication for user listings and check ownership on every object access."),
    "GENERIC-IDOR-002": ExploitLesson(
        "Insecure direct object reference (orders)", "A01 Broken Access Control",
        "T1213 Data from Information Repositories",
        "Walking order ids in the WooCommerce REST API reads other customers' orders if "
        "the endpoint does not verify who owns each one.",
        "Check ownership on every object, use authenticated API keys, and avoid guessable "
        "sequential ids where possible."),
    "GENERIC-TOOL-001": ExploitLesson(
        "Automated SQL injection tool", "A03 Injection",
        "T1595.002 Active Scanning: Vulnerability Scanning",
        "sqlmap announces itself in its User-Agent. Detecting the tool by name is easy to "
        "evade (attackers change the header) but catches careless automation.",
        "Do not rely on User-Agent alone: also detect the payloads and request rates."),
    "GENERIC-TOOL-002": ExploitLesson(
        "Automated web scanner (Nikto)", "A05 Security Misconfiguration",
        "T1595.002 Active Scanning: Vulnerability Scanning",
        "Nikto sends thousands of requests for known-bad files and identifies itself in the "
        "User-Agent unless told otherwise.",
        "Detect scanner bursts by behaviour (many 404s, known-bad paths), not just by name."),
    "GENERIC-TOOL-003": ExploitLesson(
        "Exploitation framework (Metasploit)", "A06 Vulnerable and Outdated Components",
        "T1595.002 Active Scanning: Vulnerability Scanning",
        "Metasploit modules normally send a browser-like User-Agent, so a name match is a "
        "weak signal. This preset sends an honest agent to show that name-based detection "
        "works only for the unevasive case.",
        "Detect the exploit payloads and post-exploitation behaviour, not the framework name."),
    "GENERIC-TOOL-004": ExploitLesson(
        "Directory brute-forcer (Gobuster)", "A05 Security Misconfiguration",
        "T1595.003 Active Scanning: Wordlist Scanning",
        "Gobuster requests every entry of a wordlist and keeps the paths that exist. Its "
        "default User-Agent is gobuster/<version>.",
        "Rate-limit and flag clients with many 404s in a short time."),
    "GENERIC-TOOL-005": ExploitLesson(
        "WordPress scanner (WPScan)", "A06 Vulnerable and Outdated Components",
        "T1595.002 Active Scanning: Vulnerability Scanning",
        "WPScan enumerates WordPress version, plugins, themes and users, and matches them "
        "against a vulnerability database. Its default User-Agent names it.",
        "Hide version information, restrict user enumeration, and flag WPScan-style probing."),
    "CVE-2024-25600": ExploitLesson(
        "Remote code execution (code injection)", "A03 Injection", _T1190,
        "Bricks Builder's render_element endpoint passes attacker-supplied PHP to eval() "
        "without logging in. The payload runs system('id') to prove command execution.",
        "Never eval() user input; require authentication and nonces; update Bricks "
        "(fixed in 1.9.6.1)."),
    "CVE-2024-27956": ExploitLesson(
        "SQL injection", "A03 Injection", _T1190,
        "WP Automatic's csv.php runs a query built from the q parameter without "
        "authentication. It was mass-exploited to create rogue admin accounts. " + _SQLI_HOW,
        _SQLI_DEFENCE),
    "CVE-2024-1071": ExploitLesson(
        "SQL injection", "A03 Injection", _T1190,
        "Ultimate Member's um_get_members AJAX action puts directory_id into a query "
        "unescaped. " + _SQLI_HOW, _SQLI_DEFENCE),
    "CVE-2022-0739": ExploitLesson(
        "SQL injection", "A03 Injection", _T1190,
        "BookingPress passes total_service into a query unescaped. " + _SQLI_HOW,
        _SQLI_DEFENCE),
    "CVE-2024-2879": ExploitLesson(
        "SQL injection", "A03 Injection", _T1190,
        "LayerSlider's ls_get_popup_markup action puts id into a query unescaped. " + _SQLI_HOW,
        _SQLI_DEFENCE),
}


def lesson_for(cve: str) -> ExploitLesson | None:
    return EXPLOIT_LESSONS.get(cve)


# ---- threat-analyzer event explanations ----

# (substring of the event label, lower-case) -> explanation. Checked in order,
# first match wins, so more specific phrases come first. Labels come from
# core/threat_log_parser (which mirrors threat_analyzer.lua / router.lua).
_EVENT_EXPLANATIONS: list[tuple[str, str]] = [
    ("cve", "The request matched the known pattern of a published vulnerability (CVE). "
            "A CVE match alone is enough to divert the session to the honeypot."),
    ("uri pattern", "The URL contains patterns typical of attacks or probing, such as "
                    "../, SQL keywords or requests for sensitive files."),
    ("suspicious header", "A request header looks forged or tool-generated, for example an "
                          "exploit-specific header or a missing/odd User-Agent."),
    ("bad ip reputation", "This IP address has a bad reputation from earlier alerts "
                          "(Suricata, previous honeypot hits or threat-intel feeds)."),
    ("known threat ip", "This IP address is already on the known-threat list, so its "
                        "requests start with extra suspicion."),
    ("whitelisted", "This IP address is trusted, so its score is lowered."),
    ("request method", "An unusual HTTP method (such as PUT, DELETE or TRACE) for a "
                       "public shop."),
    ("automation", "The client looks like a script or scanner (curl, sqlmap, a headless "
                   "browser) rather than a person in a browser."),
    ("upload", "The request uploads a file that looks dangerous, such as a .php web shell "
               "or a mismatched MIME type."),
    ("prompt-injection", "The request contains text crafted to manipulate an AI system "
                         "(prompt injection)."),
    ("below threshold", "This session was sent to the honeypot earlier, but its score has "
                        "decayed below the threshold, so it is allowed back to production."),
    ("staying on production", "Something looked a little suspicious and was logged, but not "
                              "enough to divert the session."),
    ("session bound", "This session was already sent to the honeypot earlier, so it stays "
                      "there (sticky session) whatever this request scores."),
    ("high threat score", "The accumulated score crossed the honeypot threshold, so the "
                          "session was diverted."),
    ("vulnerable plugin", "Direct access to a file of a plugin with a known vulnerability."),
    ("admin attempt", "Repeated attempts to reach the WordPress admin area, typical of "
                      "password guessing."),
    ("accumulated suspicious", "Many individually small suspicious actions added up to "
                               "enough evidence to divert the session."),
    ("rapid automation", "Requests are arriving too fast for a human."),
    ("final decision: honeypot", "The request was sent to the decoy shop. The attacker "
                                 "sees a normal-looking site and doesn't know."),
    ("final decision: production", "The request was judged safe and sent to the real shop."),
    ("routed to honeypot", "The request was sent to the decoy shop."),
    ("routed to production", "The request was judged safe and sent to the real shop."),
    ("final score", "The total of all signal points for this request, out of 100. The "
                    "session goes to the honeypot at the threshold (80 by default)."),
    ("clean request", "No suspicious signals at all."),
    ("low threat", "A few weak signals, but below the threshold, so it stays on production."),
    ("missing required dependency", "A tool the dashboard needs is not installed; see the "
                                    "banner at the top of the window."),
]


def explain_event(label: str) -> str:
    """Plain-language explanation of a threat-analyzer event label, or ""."""
    low = label.lower()
    for needle, text in _EVENT_EXPLANATIONS:
        if needle in low:
            return text
    return ""


# ---- guided labs ----

@dataclass(frozen=True)
class LabStep:
    id: str
    text: str
    page: str = ""  # page to open for this step ("" = none)


@dataclass(frozen=True)
class Lab:
    id: str
    title: str
    goal: str
    steps: tuple[LabStep, ...]


LABS: list[Lab] = [
    Lab("lab1", "Lab 1: Bring the system up",
        "Start both stacks and understand what each container does.",
        (
            LabStep("lab1.certs", "Generate TLS certificates (only needed once).", "certificates"),
            LabStep("lab1.start", "Start the ids project, then the siem project.", "services"),
            LabStep("lab1.health", "Wait until every node on the Health diagram is green. "
                    "Find the reverse proxy, both eshops and Suricata.", "health"),
            LabStep("lab1.glossary", "Read the glossary entries for Honeypot, Reverse proxy "
                    "and SIEM.", "learn"),
        )),
    Lab("lab2", "Lab 2: Watch a normal visitor",
        "See what a clean request looks like before attacking anything.",
        (
            LabStep("lab2.reset", "On Exploits, press 'Reset local score + cookies'.", "exploits"),
            LabStep("lab2.browse", "Browse the shop in the embedded browser for a minute.", "exploits"),
            LabStep("lab2.cards", "On the Threat analyzer tab, confirm the requests route to "
                    "PRODUCTION with a low score.", "exploits"),
        )),
    Lab("lab3", "Lab 3: Fire an SQL injection",
        "Trigger detection and follow one attack from request to routing decision.",
        (
            LabStep("lab3.read", "Select CVE-2024-27956 (WP Automatic SQLi) and press "
                    "'What is this?' to read how it works.", "exploits"),
            LabStep("lab3.run", "Press 'Run exploit (curl)'.", "exploits"),
            LabStep("lab3.signals", "On the Threat analyzer tab, find each signal and its points. "
                    "Hover a card for an explanation.", "exploits"),
            LabStep("lab3.route", "Confirm the final decision is HONEYPOT and note the score.",
                    "exploits"),
            LabStep("lab3.redis", "Find your session and its stored score in Redis.", "redis"),
        )),
    Lab("lab4", "Lab 4: Investigate in the SIEM",
        "Find the same attack as an analyst would, in Kibana and the raw logs.",
        (
            LabStep("lab4.kibana", "Open Attack Patterns and find the CVE under Top CVEs "
                    "Detected.", "kibana"),
            LabStep("lab4.discover", "Open Discover and filter to your IP address.", "kibana"),
            LabStep("lab4.logs", "Search the raw logs for the CVE ID.", "log_search"),
        )),
    Lab("lab5", "Lab 5: Tune the detector",
        "See how configuration changes who counts as an attacker.",
        (
            LabStep("lab5.unpoison", "Press 'Unpoison host IP' to start clean.", "exploits"),
            LabStep("lab5.run", "Select CVE-2024-27956, press 'Run exploit (browser)' and "
                    "confirm the browser's session is routed to HONEYPOT.", "exploits"),
            LabStep("lab5.decay", "Wait five minutes (one half-life: 100 decays to 50, under the "
                    "threshold), browse the shop again and watch the route.", "exploits"),
            LabStep("lab5.nodecay", "Set THREAT_DECAY_ENABLED=false in the edge .env, restart ids "
                    "and repeat. What changed, and why does never forgiving raise false "
                    "positives?", "settings"),
            LabStep("lab5.restore", "Put the setting back and restart ids.", "settings"),
        )),
]


def all_step_ids() -> list[str]:
    return [s.id for lab in LABS for s in lab.steps]


def lab_progress(lab: Lab, completed: set[str] | list[str]) -> tuple[int, int]:
    """(done, total) for one lab given the completed step ids."""
    done_ids = set(completed)
    return sum(1 for s in lab.steps if s.id in done_ids), len(lab.steps)
