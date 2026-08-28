# nmap2html

Turn an Nmap XML scan into a clean, interactive, self-contained HTML report — no server, no dependencies, just open it in a browser.

```bash
nmap -sC -sV -A <target> -oX scan.xml
python3 nmap2html.py scan.xml
google-chrome scan.html
```

## Features

- **Detail view** — one panel per host: status, best OS guess, MAC/vendor, open ports, service/version info, and NSE script output (host- and port-level).
- **Sheet view** — a flat, searchable table of every host/port combo across the whole scan, for quickly scanning large result sets.
- **Review tracking** — mark hosts as reviewed; state is kept in the browser's `localStorage`, shared between Detail and Sheet views, and persists across reloads.
- **Clickable targets** — when a host has an open HTTP/HTTPS service, its name and IP become links that open the site in a new tab.
- **Zero dependencies** — pure Python 3 standard library. The output is static HTML/CSS/JS you can hand off or host anywhere.

## Requirements

- Python 3.9+
- Nmap, run with XML output (`-oX`)

## Usage

```bash
python3 nmap2html.py scan.xml                    # writes scan.html + assets/
python3 nmap2html.py scan.xml -o assessment.html  # custom output name
python3 nmap2html.py -h                           # full help, flags, workflow
```

Each run produces:

```text
<name>.html
assets/report.css
assets/report.js
```

## Workflow

```bash
# 1) Scan and save results as XML
nmap -sC -sV -A <target> -oX scan.xml
nmap -sC -sV -A -iL targets.txt -oX scan.xml   # multiple targets

# 2) Generate the report
python3 nmap2html.py scan.xml

# 3) Open it
google-chrome scan.html
```

## Target links

When an open HTTP/HTTPS service is detected, the host name and IP in the report become clickable links (`target="_blank"`, `rel="noopener noreferrer"`).

The generator prefers standard ports 80/443, then common web ports (8000, 8080, 8081, 8443, 8888, 9443). Nmap service names containing `http`, HTTPS/SSL service names, and `tunnel="ssl"` are also recognized.

## Project structure

```text
nmap2html/
├── nmap2html.py        # CLI entry point / XML parser / HTML builder
├── templates/
│   └── report.html      # HTML skeleton with placeholder markers
├── assets/
│   ├── report.css       # report styling
│   └── report.js        # view switching, search, review-state
└── sample.xml            # example Nmap XML for testing
```

## Notes

- Only scan systems you are explicitly authorized to test.
- The generated report is fully static — `.html` + `assets/report.{css,js}` — and safe to open offline.
