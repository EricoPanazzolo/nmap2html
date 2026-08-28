#!/usr/bin/env python3
"""nmap2html project v2.0 - Convert Nmap XML into a static HTML report project."""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

VERSION = "2.2"
PROJECT_DIR = Path(__file__).resolve().parent
TEMPLATE_FILE = PROJECT_DIR / "templates" / "report.html"
ASSET_DIR = PROJECT_DIR / "assets"

BANNER_ART = r"""
                               ___   __    __            __
   ____  ____ ___  ____ _____ |__ \ / /_  / /_____ ___  / /
  / __ \/ __ `__ \/ __ `/ __ \__/ // __ \/ __/ __ `__ \/ /
 / / / / / / / / / /_/ / /_/ / __// / / / /_/ / / / / / /
/_/ /_/_/ /_/ /_/\__,_/ .___/____/_/ /_/\__/_/ /_/ /_/_/
                     /_/
""".strip("\n")


def _use_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"


def print_banner() -> None:
    rule = "─" * 78
    if not _use_color():
        print(f"nmap2html project v{VERSION}")
        print(rule)
        return

    bold, dim, reset = "\033[1m", "\033[2m", "\033[0m"
    # cyan -> teal -> green gradient, top to bottom
    gradient = ["\033[38;5;51m", "\033[38;5;45m", "\033[38;5;44m", "\033[38;5;43m", "\033[38;5;42m", "\033[38;5;41m"]
    lines = BANNER_ART.splitlines()
    print()
    for line, color in zip(lines, gradient):
        print(f"{bold}{color}{line}{reset}")
    print(f"  {dim}Nmap XML {reset}{bold}→{reset}{dim} interactive HTML reports{reset}   {dim}v{VERSION}{reset}")
    print(f"{dim}{rule}{reset}")


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def parse_epoch(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return dt.datetime.fromtimestamp(int(value)).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    except (ValueError, TypeError, OSError, OverflowError):
        return value


def parse_script(el: ET.Element) -> Dict[str, str]:
    return {"id": el.attrib.get("id", ""), "output": el.attrib.get("output", "")}


def parse_host(host_el: ET.Element, index: int) -> Dict[str, Any]:
    status_el = host_el.find("status")
    state = status_el.attrib.get("state", "unknown") if status_el is not None else "unknown"
    state_reason = status_el.attrib.get("reason", "") if status_el is not None else ""

    ipv4 = ipv6 = mac = vendor = ""
    for el in host_el.findall("address"):
        typ = el.attrib.get("addrtype", "")
        addr = el.attrib.get("addr", "")
        if typ == "ipv4" and not ipv4:
            ipv4 = addr
        elif typ == "ipv6" and not ipv6:
            ipv6 = addr
        elif typ == "mac" and not mac:
            mac = addr
            vendor = el.attrib.get("vendor", "")

    hostnames = [e.attrib.get("name", "") for e in host_el.findall("./hostnames/hostname")]
    hostnames = [x for x in hostnames if x]

    ports: List[Dict[str, Any]] = []
    for port_el in host_el.findall("./ports/port"):
        state_el = port_el.find("state")
        port_state = state_el.attrib.get("state", "") if state_el is not None else ""
        if port_state != "open":
            continue
        service_el = port_el.find("service")
        service = {"name": "", "product": "", "version": "", "extrainfo": "", "tunnel": ""}
        if service_el is not None:
            for key in service:
                service[key] = service_el.attrib.get(key, "")
        ports.append({
            "portid": port_el.attrib.get("portid", ""),
            "protocol": port_el.attrib.get("protocol", ""),
            "state": port_state,
            "state_reason": state_el.attrib.get("reason", "") if state_el is not None else "",
            "service": service,
            "scripts": [parse_script(x) for x in port_el.findall("script")],
        })

    os_matches = []
    for match in host_el.findall("./os/osmatch"):
        if match.attrib.get("name"):
            os_matches.append({"name": match.attrib.get("name", ""), "accuracy": match.attrib.get("accuracy", "")})
    os_matches.sort(key=lambda x: int(x["accuracy"]) if x["accuracy"].isdigit() else -1, reverse=True)
    best_os = os_matches[0] if os_matches else {"name": "", "accuracy": ""}

    ip = ipv4 or ipv6
    display_name = (hostnames[0] if hostnames else "") or ip or mac or f"Host {index + 1}"
    # Review state must be unique per parsed host.
    # Using only the IP caused multiple host entries with the same address to
    # share a localStorage key and therefore toggle together.  Keep the human
    # identity in the key, but append the stable XML host index so every target
    # in this report owns an independent review state.
    storage_identity = ip or display_name or mac or "host"
    storage_key = f"{storage_identity}::host-{index + 1}"

    host = {
        "index": index,
        "state": state,
        "state_reason": state_reason,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "hostnames": hostnames,
        "hostname": hostnames[0] if hostnames else "",
        "display_name": display_name,
        "storage_key": storage_key,
        "ports": ports,
        "open_port_count": len(ports),
        "best_os": best_os,
        "os_matches": os_matches,
        "host_scripts": [parse_script(x) for x in host_el.findall("./hostscript/script")],
    }
    host["web_url"] = derive_web_url(host)
    return host


def parse_nmap_xml(path: Path) -> Dict[str, Any]:
    root = ET.parse(path).getroot()
    finished = root.find("./runstats/finished")
    hosts = [parse_host(h, i) for i, h in enumerate(root.findall("host"))]
    return {
        "nmap_version": root.attrib.get("version", ""),
        "args": root.attrib.get("args", ""),
        "start_time": parse_epoch(root.attrib.get("start")),
        "finish_time": parse_epoch(finished.attrib.get("time") if finished is not None else None),
        "hosts": hosts,
    }


def format_version(service: Dict[str, str]) -> str:
    return " ".join(x for x in (service.get("product", ""), service.get("version", ""), service.get("extrainfo", "")) if x)


def is_web_service(port: Dict[str, Any]) -> bool:
    name = (port["service"].get("name") or "").lower()
    product = (port["service"].get("product") or "").lower()
    return "http" in name or "http" in product or port["portid"] in {"80", "443", "8000", "8080", "8081", "8443", "8888", "9443"}


def derive_web_url(host: Dict[str, Any]) -> str:
    hostname = host.get("hostname") or host.get("ip") or ""
    if not hostname:
        return ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    candidates = [p for p in host.get("ports", []) if p.get("protocol") == "tcp" and is_web_service(p)]
    if not candidates:
        return ""

    def score(port: Dict[str, Any]) -> tuple[int, int]:
        p = int(port["portid"]) if str(port["portid"]).isdigit() else 65535
        name = (port["service"].get("name") or "").lower()
        tunnel = (port["service"].get("tunnel") or "").lower()
        secure = p in {443, 8443, 9443} or tunnel == "ssl" or "https" in name or "ssl" in name
        standard = p in {80, 443}
        return (0 if standard else 1, 0 if secure else 1)

    port = sorted(candidates, key=score)[0]
    p = int(port["portid"]) if str(port["portid"]).isdigit() else 0
    name = (port["service"].get("name") or "").lower()
    tunnel = (port["service"].get("tunnel") or "").lower()
    https = p in {443, 8443, 9443} or tunnel == "ssl" or "https" in name or "ssl" in name
    scheme = "https" if https else "http"
    suffix = "" if (scheme == "http" and p == 80) or (scheme == "https" and p == 443) else f":{p}"
    return f"{scheme}://{hostname}{suffix}/"


def render_scripts(scripts: List[Dict[str, str]], title: str = "NSE scripts") -> str:
    if not scripts:
        return ""
    body = "".join(
        '<details class="nse"><summary><span class="mono">{}</span></summary><pre>{}</pre></details>'.format(
            esc(s.get("id") or "script"), esc(s.get("output") or "")
        )
        for s in scripts
    )
    return f'<div class="nse-group"><div class="section-label">{esc(title)}</div>{body}</div>'


def target_link(host: Dict[str, Any], text: str) -> str:
    if not host.get("web_url"):
        return esc(text)
    return '<a class="target-link" href="{}" target="_blank" rel="noopener noreferrer">{}</a>'.format(
        esc(host["web_url"]), esc(text)
    )


def render_host_detail(host: Dict[str, Any], index: int) -> str:
    rows = []
    for port in host["ports"]:
        rows.append(
            "<tr>"
            f'<td class="mono nowrap">{esc(port["portid"] + "/" + port["protocol"])}</td>'
            f'<td>{esc(port["service"].get("name") or "—")}</td>'
            f'<td><div>{esc(format_version(port["service"]) or "—")}</div>{render_scripts(port["scripts"])}</td>'
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="3" class="empty">No open ports found.</td></tr>')

    os_name = esc(host["best_os"].get("name") or "—")
    acc = esc(host["best_os"].get("accuracy") or "")
    os_display = os_name + (f' <span class="muted">({acc}% accuracy)</span>' if acc else "")
    mac_display = esc(host["mac"] or "—") + (f' <span class="muted">({esc(host["vendor"])})</span>' if host["vendor"] else "")
    web_hint = f'<div class="subtle">Web: <a href="{esc(host["web_url"])}" target="_blank" rel="noopener noreferrer">{esc(host["web_url"])}</a></div>' if host["web_url"] else ""

    return f'''<section class="host-panel" data-host-index="{index}" data-host-panel="{esc(host['storage_key'])}">
  <div class="host-heading"><div><h2>{target_link(host, host['display_name'])}</h2><div class="subtle">Host details and open services</div>{web_hint}</div>
  <button type="button" class="review-btn" data-action="toggle-review" data-host-key="{esc(host['storage_key'])}">Mark as reviewed</button></div>
  <div class="meta-grid">
    <div class="meta-item"><span>Hostname</span><strong>{target_link(host, host['hostname'] or '—')}</strong></div>
    <div class="meta-item"><span>IP</span><strong class="mono">{target_link(host, host['ip'] or '—')}</strong></div>
    <div class="meta-item"><span>Status</span><strong>{esc(host['state'])}</strong>{f'<small>{esc(host["state_reason"])}</small>' if host['state_reason'] else ''}</div>
    <div class="meta-item"><span>Best OS guess</span><strong>{os_display}</strong></div>
    <div class="meta-item"><span>MAC</span><strong class="mono">{mac_display}</strong></div>
    <div class="meta-item"><span>Open ports</span><strong>{host['open_port_count']}</strong></div>
  </div>
  <div class="table-wrap"><table class="ports-table"><thead><tr><th>Port</th><th>Service</th><th>Version / Details</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
  {render_scripts(host['host_scripts'], 'Host-level NSE scripts')}
</section>'''


def render_sheet_rows(hosts: List[Dict[str, Any]]) -> str:
    out = []
    for host in hosts:
        ports = host["ports"] or [None]
        for idx, port in enumerate(ports):
            first = idx == 0
            port_text = "—" if port is None else f"{port['portid']}/{port['protocol']}"
            service_name = "—" if port is None else (port["service"].get("name") or "—")
            version_text = "—" if port is None else (format_version(port["service"]) or "—")
            os_text = host["best_os"].get("name") or "—"
            if host["best_os"].get("accuracy"):
                os_text += f" ({host['best_os']['accuracy']}%)"
            searchable = " ".join([host["display_name"], host["hostname"], host["ip"], os_text, port_text, service_name, version_text]).lower()
            first_cells = (
                f'<td><button type="button" class="done-control" data-action="toggle-review" data-host-key="{esc(host["storage_key"])}"><span class="done-box">✓</span></button></td>'
                f'<td>{target_link(host, host["display_name"])}</td><td class="mono">{target_link(host, host["ip"] or "—")}</td><td>{esc(host["state"])}</td><td>{esc(os_text)}</td>'
            ) if first else '<td class="continuation">↳</td><td class="muted">↳</td><td></td><td></td><td></td>'
            out.append(
                f'<tr data-host-key="{esc(host["storage_key"])}" data-search="{esc(searchable)}">{first_cells}'
                f'<td class="mono nowrap">{esc(port_text)}</td><td>{esc(service_name)}</td><td>{esc(version_text)}</td></tr>'
            )
    return "".join(out)


def safe_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def build_html(report: Dict[str, Any], source_name: str, css_href: str, js_src: str) -> str:
    hosts = report["hosts"]
    template = TEMPLATE_FILE.read_text(encoding="utf-8")
    tabs = ""
    if len(hosts) > 1:
        buttons = []
        for idx, host in enumerate(hosts):
            buttons.append(
                f'<button type="button" class="host-tab{" active" if idx == 0 else ""}" data-action="switch-host" data-host-index="{idx}" data-host-key="{esc(host["storage_key"])}">'
                f'<span class="tab-review">✓</span><span class="tab-name">{esc(host["display_name"])}</span><span class="tab-count">{host["open_port_count"]}</span></button>'
            )
        tabs = '<div class="host-tabs" role="tablist">' + "".join(buttons) + "</div>"

    panels = []
    for idx, host in enumerate(hosts):
        panel = render_host_detail(host, idx)
        if idx:
            panel = panel.replace('class="host-panel"', 'class="host-panel hidden"', 1)
        panels.append(panel)

    replacements = {
        "__CSS_HREF__": esc(css_href), "__JS_SRC__": esc(js_src), "__SOURCE_NAME__": esc(source_name),
        "__TOTAL_TARGETS__": str(len(hosts)), "__HOSTS_UP__": str(sum(h["state"] == "up" for h in hosts)),
        "__TOTAL_OPEN_PORTS__": str(sum(h["open_port_count"] for h in hosts)), "__NMAP_VERSION__": esc(report["nmap_version"] or "—"),
        "__START_TIME__": esc(report["start_time"] or "—"), "__FINISH_TIME__": esc(report["finish_time"] or "—"),
        "__NMAP_ARGS__": esc(report["args"] or "—"), "__TABS_HTML__": tabs, "__PANELS_HTML__": "".join(panels),
        "__NO_HOSTS__": '' if hosts else '<div class="card empty-state"><h2>No hosts found</h2></div>',
        "__SHEET_ROWS__": render_sheet_rows(hosts) or '<tr><td colspan="8" class="empty">No hosts found.</td></tr>',
        "__HOST_KEYS_JSON__": safe_json([h["storage_key"] for h in hosts]),
    }
    for marker, value in replacements.items():
        template = template.replace(marker, value)
    return template


def resolve_output(input_path: Path, custom: Optional[str]) -> Path:
    return Path(custom) if custom else input_path.with_suffix(".html")


def copy_assets(output_html: Path) -> None:
    dest = output_html.parent / "assets"
    dest.mkdir(parents=True, exist_ok=True)
    for name in ("report.css", "report.js"):
        shutil.copy2(ASSET_DIR / name, dest / name)


def main() -> int:
    description = """
Generate a clean, interactive HTML report from an Nmap XML scan.
Input must be XML produced with Nmap's -oX option.
"""

    epilog = """
WORKFLOW
──────────────────────────────────────────────────────────────────────────────

  1) Scan and save the results as XML

       nmap -sC -sV -A <target> -oX nmap-output.xml
       nmap -sC -sV -A -iL targets.txt -oX nmap-output.xml   (multiple targets)

  2) Generate the HTML report

       python3 nmap2html.py nmap-output.xml
       python3 nmap2html.py nmap-output.xml -o assessment.html   (custom name)

  3) Open it

       google-chrome nmap-output.html


NMAP FLAGS USED ABOVE
──────────────────────────────────────────────────────────────────────────────

  -sC            run Nmap's default NSE scripts
  -sV            detect service and version info
  -A             OS detection + version detection + scripts + traceroute
  -iL <file>     read targets from a file, one per line
  -oX <file>     write results as XML — required by nmap2html


NOTES
──────────────────────────────────────────────────────────────────────────────

  • Only scan systems you are explicitly authorized to test.
  • The generated report is self-contained: HTML + assets/report.{css,js}.

──────────────────────────────────────────────────────────────────────────────
"""

    parser = argparse.ArgumentParser(
        prog="nmap2html.py",
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "xml",
        nargs="?",
        metavar="NMAP_XML",
        help="Nmap XML file to convert, e.g. nmap-output.xml",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="HTML",
        help="Custom HTML output path, e.g. report.html",
    )

    print_banner()

    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    args = parser.parse_args()

    if not args.xml:
        parser.print_help()
        return 0

    input_path = Path(args.xml)
    output_html = resolve_output(input_path, args.output)

    print(f"  Input   : {input_path}")
    print(f"  Output  : {output_html}")
    print("─" * 78)

    if not input_path.is_file():
        print()
        print(f"[!] Input file not found: {input_path}", file=sys.stderr)
        print()
        print("Generate an Nmap XML file first:")
        print()
        print("    nmap -sC -sV -A <target> -oX nmap-output.xml")
        print()
        print("Or scan a target list:")
        print()
        print("    nmap -sC -sV -A -iL targets.txt -oX nmap-output.xml")
        print()
        return 2

    for required in (TEMPLATE_FILE, ASSET_DIR / "report.css", ASSET_DIR / "report.js"):
        if not required.is_file():
            print()
            print(f"[!] Project file missing: {required}", file=sys.stderr)
            return 2

    try:
        report = parse_nmap_xml(input_path)
    except ET.ParseError as exc:
        print()
        print(f"[!] Invalid Nmap XML: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print()
        print(f"[!] Could not read input file: {exc}", file=sys.stderr)
        return 2

    hosts = report["hosts"]
    hosts_up = sum(1 for host in hosts if host["state"] == "up")
    total_open_ports = sum(host["open_port_count"] for host in hosts)

    print()
    print("[+] Nmap XML parsed successfully")
    print()
    print(f"    Nmap version : {report.get('nmap_version') or 'Unknown'}")
    print(f"    Targets      : {len(hosts)}")
    print(f"    Hosts up     : {hosts_up}")
    print(f"    Open ports   : {total_open_ports}")

    if report.get("start_time"):
        print(f"    Scan started : {report['start_time']}")
    if report.get("finish_time"):
        print(f"    Scan finished: {report['finish_time']}")
    if report.get("args"):
        print(f"    Command      : {report['args']}")

    if hosts:
        print()
        print("[+] Discovered targets")
        print()

        for index, host in enumerate(hosts, start=1):
            target = (
                host.get("hostname")
                or host.get("ipv4")
                or host.get("ipv6")
                or host.get("display_name")
                or "Unknown target"
            )
            ip = host.get("ipv4") or host.get("ipv6") or "—"
            state = host.get("state", "unknown")
            open_ports = host.get("open_port_count", 0)
            os_text = host.get("best_os", {}).get("name") or "unknown OS"
            os_accuracy = host.get("best_os", {}).get("accuracy") or ""
            if os_accuracy:
                os_text += f" ({os_accuracy}%)"

            print(
                f"    [{index:02d}] {target}"
                f" | {ip}"
            )

    try:
        output_html.parent.mkdir(parents=True, exist_ok=True)
        copy_assets(output_html)
        html_report = build_html(
            report,
            input_path.name,
            "assets/report.css",
            "assets/report.js",
        )
        output_html.write_text(html_report, encoding="utf-8")
    except OSError as exc:
        print()
        print(f"[!] Could not write report project: {exc}", file=sys.stderr)
        return 2

    print()
    print("─" * 78)
    print("[+] Report generated successfully")
    print()
    print(f"    HTML       : {output_html}")
    print(f"    CSS        : {output_html.parent / 'assets' / 'report.css'}")
    print(f"    JavaScript : {output_html.parent / 'assets' / 'report.js'}")

    try:
        print(f"    HTML size  : {output_html.stat().st_size:,} bytes")
    except OSError:
        pass

    print("    Target URLs: open in a new browser tab/window when a web service is detected")
    print("    Review     : localStorage-backed state shared by Detail and Sheet views")
    print()
    print("Open the report with:")
    print()
    print(f"    xdg-open {output_html}")
    print()
    print("─" * 78)
    print()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
