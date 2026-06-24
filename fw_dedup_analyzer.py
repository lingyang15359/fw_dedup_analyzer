#!/usr/bin/env python3
"""
Firewall Configuration Duplicate Object Analyzer
=================================================

Scans two or more Cisco ASA / FTD style configuration files and reports
network objects, service objects, and object-groups that share identical
or effectively-identical content.

Matching rules (per system prompt):
  1. Literal object duplicates - different `object network` / `object service`
     names that resolve to the same host/subnet/range/fqdn or protocol/port.
  2. Literal group duplicates - different `object-group` definitions whose
     direct members are identical (order-insensitive).
  3. Effective/functional duplicates - groups whose *resolved* set of IPs
     or ports is identical, even when the literal members differ.

Usage:
    python3 fw_dedup_analyzer.py <config1> <config2> [<config3> ...] \\
        [-o report.md] [--include-same-file] [--json results.json]

Pure standard library - no third-party dependencies. Python 3.7+.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from typing import Dict, FrozenSet, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Port / service name aliases (ASA well-known names -> numeric port strings)
# ---------------------------------------------------------------------------
PORT_ALIAS: Dict[str, str] = {
    "www": "80", "http": "80", "https": "443", "ftp": "21", "ftp-data": "20",
    "ssh": "22", "telnet": "23", "smtp": "25", "domain": "53", "pop3": "110",
    "nntp": "119", "imap4": "143", "ldap": "389", "ldaps": "636",
    "sqlnet": "1521", "sip": "5060", "h323": "1720", "cmd": "514", "rsh": "514",
    "exec": "512", "klogin": "543", "kshell": "544", "login": "513", "lpd": "515",
    "whois": "43", "gopher": "70", "finger": "79", "hostname": "101",
    "ident": "113", "irc": "194", "tacacs": "49", "talk": "517", "uucp": "540",
    "echo": "7", "discard": "9", "daytime": "13", "chargen": "19", "time": "37",
    "pim-auto-rp": "496", "bgp": "179", "ctiqbe": "2748", "cifs": "3020",
    "ntp": "123", "snmp": "161", "snmptrap": "162", "syslog": "514", "tftp": "69",
    "isakmp": "500", "nameserver": "42", "kerberos": "750", "radius": "1645",
    "radius-acct": "1646", "secureid-udp": "5510", "biff": "512", "bootpc": "68",
    "bootps": "67", "netbios-ns": "137", "netbios-dgm": "138", "netbios-ssn": "139",
    "mobile-ip": "434", "who": "513", "xdmcp": "177", "rip": "520",
    "pcanywhere-status": "5632", "pcanywhere-data": "5631", "non500-isakmp": "4500",
    "nfs": "2049", "rtsp": "554", "sunrpc": "111", "aol": "5190", "msrpc": "135",
    "ldap-admin": "3268",
}


def norm_port(token: str) -> str:
    return PORT_ALIAS.get(token.lower(), token)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
def normalize_port_token(s: str) -> Tuple:
    """Normalize a `port-object ...` payload to a canonical tuple."""
    parts = s.split()
    if not parts:
        return ()
    if parts[0] == "eq" and len(parts) == 2:
        return ("eq", norm_port(parts[1]))
    if parts[0] == "range" and len(parts) == 3:
        return ("range", norm_port(parts[1]), norm_port(parts[2]))
    return tuple(parts)


def normalize_service_line(payload: str) -> Optional[Tuple]:
    """
    Normalize a `service ...` body (object service) or `service-object ...` line
    body to a canonical (proto, src, dst) tuple. `src`/`dst` are None or
    tuples like ("eq", "443") / ("range", "1000", "2000").
    """
    parts = payload.split()
    if not parts:
        return None
    proto = parts[0]
    rest = parts[1:]
    src: Optional[Tuple] = None
    dst: Optional[Tuple] = None
    j = 0
    while j < len(rest):
        if rest[j] == "source" and j + 2 < len(rest):
            op = rest[j + 1]
            if op == "range" and j + 3 < len(rest):
                src = ("range", norm_port(rest[j + 2]), norm_port(rest[j + 3]))
                j += 4
            else:
                src = (op, norm_port(rest[j + 2]))
                j += 3
        elif rest[j] == "destination" and j + 2 < len(rest):
            op = rest[j + 1]
            if op == "range" and j + 3 < len(rest):
                dst = ("range", norm_port(rest[j + 2]), norm_port(rest[j + 3]))
                j += 4
            else:
                dst = (op, norm_port(rest[j + 2]))
                j += 3
        else:
            j += 1
    return (proto, src, dst)


def parse_config(path: str) -> Tuple[Dict, Dict, Dict]:
    """
    Parse an ASA/FTD config file.

    Returns (nets, svcs, groups):
        nets   : { name -> ("host", ip) | ("subnet", net, mask) | ("range", a, b) | ("fqdn", value) }
        svcs   : { name -> (proto, src, dst) }
        groups : { name -> {"kind": ..., "proto": ..., "items": [...], "raw": [...]} }
    """
    nets: Dict[str, Tuple] = {}
    svcs: Dict[str, Tuple] = {}
    groups: Dict[str, Dict] = {}

    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    i, n = 0, len(lines)
    while i < n:
        line = lines[i]

        m = re.match(r"^object network (\S+)\s*$", line)
        if m:
            name = m.group(1)
            i += 1
            body = None
            while i < n and lines[i].startswith(" "):
                s = lines[i].strip()
                if s.startswith("host "):
                    body = ("host", s.split()[1])
                elif s.startswith("subnet "):
                    parts = s.split()
                    body = ("subnet", parts[1], parts[2]) if len(parts) >= 3 else ("subnet", parts[1])
                elif s.startswith("range "):
                    parts = s.split()
                    if len(parts) >= 3:
                        body = ("range", parts[1], parts[2])
                elif s.startswith("fqdn "):
                    parts = s.split()
                    body = ("fqdn", parts[-1])
                i += 1
            if body:
                nets[name] = body
            continue

        m = re.match(r"^object service (\S+)\s*$", line)
        if m:
            name = m.group(1)
            i += 1
            body = None
            while i < n and lines[i].startswith(" "):
                s = lines[i].strip()
                if s.startswith("service "):
                    body = normalize_service_line(s[len("service "):])
                i += 1
            if body:
                svcs[name] = body
            continue

        m = re.match(r"^object-group (network|service|protocol|icmp-type) (\S+)(?:\s+(\S+))?\s*$", line)
        if m:
            kind, name, proto = m.group(1), m.group(2), m.group(3)
            i += 1
            items: List[Tuple] = []
            raw: List[str] = []
            while i < n and lines[i].startswith(" "):
                s = lines[i].strip()
                raw.append(s)
                if s.startswith("network-object object "):
                    items.append(("netobj", s.split()[2]))
                elif s.startswith("network-object host "):
                    items.append(("host", s.split()[2]))
                elif s.startswith("network-object "):
                    parts = s.split()
                    if len(parts) >= 3:
                        items.append(("subnet", parts[1], parts[2]))
                    elif len(parts) == 2:
                        items.append(("subnet", parts[1]))
                elif s.startswith("group-object "):
                    items.append(("grp", s.split()[1]))
                elif s.startswith("service-object object "):
                    items.append(("svcobj", s.split()[2]))
                elif s.startswith("service-object "):
                    svc = normalize_service_line(s[len("service-object "):])
                    if svc:
                        items.append(("svc", svc))
                elif s.startswith("port-object "):
                    items.append(("port", normalize_port_token(s[len("port-object "):])))
                elif s.startswith("protocol-object "):
                    items.append(("proto", s.split()[1]))
                elif s.startswith("icmp-object "):
                    items.append(("icmp", s.split()[1]))
                i += 1
            groups[name] = {"kind": kind, "proto": proto, "items": items, "raw": raw}
            continue

        i += 1

    return nets, svcs, groups


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------
def resolve_group(data: Dict[str, Tuple[Dict, Dict, Dict]],
                  label: str, name: str,
                  seen: Optional[set] = None) -> FrozenSet:
    """Recursively resolve a group into a frozenset of leaf elements."""
    if seen is None:
        seen = set()
    key = (label, name)
    if key in seen:
        return frozenset()
    seen.add(key)

    nets, svcs, groups = data[label]
    g = groups.get(name)
    if not g:
        return frozenset()

    out = set()
    proto_hint = g.get("proto")
    for it in g["items"]:
        t = it[0]
        if t == "netobj":
            ref = nets.get(it[1])
            out.add(("net",) + ref if ref else ("netobj_unresolved", it[1]))
        elif t == "host":
            out.add(("net", "host", it[1]))
        elif t == "subnet":
            out.add(("net",) + tuple(it))
        elif t == "grp":
            out |= resolve_group(data, label, it[1], seen)
        elif t == "svcobj":
            ref = svcs.get(it[1])
            out.add(("svc", ref) if ref else ("svcobj_unresolved", it[1]))
        elif t == "svc":
            out.add(("svc", it[1]))
        elif t == "port":
            out.add(("port", it[1], proto_hint))
        elif t == "proto":
            out.add(("proto", it[1]))
        elif t == "icmp":
            out.add(("icmp", it[1]))
    return frozenset(out)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def fmt_net(content: Tuple) -> str:
    if content[0] == "host":
        return f"host {content[1]}"
    if content[0] == "subnet":
        return "subnet " + " ".join(content[1:])
    if content[0] == "range":
        return f"range {content[1]} {content[2]}"
    if content[0] == "fqdn":
        return f"fqdn {content[1]}"
    return str(content)


def fmt_svc(s: Tuple) -> str:
    proto, src, dst = s
    parts = [proto]
    if src:
        parts.append("source " + " ".join(map(str, src)))
    if dst:
        parts.append("destination " + " ".join(map(str, dst)))
    return " ".join(parts)


def fmt_item(it: Tuple) -> str:
    return " ".join(str(p) for p in it)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def analyze(files: List[str], include_same_file: bool = False) -> Dict:
    """Parse all files and compute duplicate buckets."""
    data: Dict[str, Tuple[Dict, Dict, Dict]] = {}
    labels: List[str] = []
    for path in files:
        label = os.path.splitext(os.path.basename(path))[0]
        # ensure uniqueness if duplicate basenames
        base = label
        suffix = 1
        while label in data:
            suffix += 1
            label = f"{base}#{suffix}"
        labels.append(label)
        data[label] = parse_config(path)

    net_buckets: Dict[Tuple, List[Tuple[str, str]]] = defaultdict(list)
    svc_buckets: Dict[Tuple, List[Tuple[str, str]]] = defaultdict(list)
    lit_buckets: Dict[Tuple, List[Tuple[str, str]]] = defaultdict(list)
    res_buckets: Dict[Tuple, List[Tuple[str, str]]] = defaultdict(list)

    for label, (nets, svcs, groups) in data.items():
        for name, body in nets.items():
            net_buckets[body].append((label, name))
        for name, body in svcs.items():
            svc_buckets[body].append((label, name))
        for name, g in groups.items():
            lit_key = (g["kind"], frozenset(tuple(x) for x in g["items"]))
            if g["items"]:
                lit_buckets[lit_key].append((label, name))
            resolved = resolve_group(data, label, name)
            if resolved:
                res_buckets[(g["kind"], resolved)].append((label, name))

    def keep(entries: List[Tuple[str, str]]) -> bool:
        if len(entries) < 2:
            return False
        if include_same_file:
            return True
        return len({e[0] for e in entries}) >= 2

    sec1 = sorted(((c, e) for c, e in net_buckets.items() if keep(e)),
                  key=lambda x: (x[0][0], str(x[0])))
    sec2 = sorted(((c, e) for c, e in svc_buckets.items() if keep(e)),
                  key=lambda x: str(x[0]))
    sec3a = [(k, v) for k, v in lit_buckets.items() if keep(v)]
    # avoid double-reporting literal matches in resolved section
    literal_entry_sets = {frozenset(v) for _, v in sec3a}
    sec3b = [(k, v) for k, v in res_buckets.items()
             if keep(v) and frozenset(v) not in literal_entry_sets]

    counts = {label: {
        "networks": len(nets),
        "services": len(svcs),
        "groups": len(groups),
    } for label, (nets, svcs, groups) in data.items()}

    return {
        "files": dict(zip(labels, files)),
        "counts": counts,
        "sec1": sec1,
        "sec2": sec2,
        "sec3a": sec3a,
        "sec3b": sec3b,
        "include_same_file": include_same_file,
    }


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------
def render_markdown(result: Dict, max_members_shown: int = 8) -> str:
    out: List[str] = []
    out.append("# Firewall Config Duplicate Object Analysis")
    out.append("")
    out.append("**Files analyzed:**")
    out.append("")
    for label, path in result["files"].items():
        out.append(f"- `{label}` -> `{path}`")
    out.append("")
    scope = "all duplicates (including same-file)" if result["include_same_file"] \
            else "cross-file matches only"
    out.append(f"**Scope:** {scope}.")
    out.append("")

    # --- Section 1
    out.append("## 1. Identical Network Objects (Same Host/Subnet/FQDN)")
    out.append("")
    if not result["sec1"]:
        out.append("_No matches._")
        out.append("")
    else:
        for content, entries in result["sec1"]:
            out.append(f"- **Content:** `{fmt_net(content)}`")
            for lbl, nm in entries:
                out.append(f"  - Object: `{nm}` ({lbl})")
        out.append("")

    # --- Section 2
    out.append("## 2. Identical Service Objects (Same Protocol/Port)")
    out.append("")
    if not result["sec2"]:
        out.append("_No matches._")
        out.append("")
    else:
        for content, entries in result["sec2"]:
            out.append(f"- **Content:** `{fmt_svc(content)}`")
            for lbl, nm in entries:
                out.append(f"  - Object: `{nm}` ({lbl})")
        out.append("")

    # --- Section 3a
    out.append("## 3. Identical Object-Groups")
    out.append("")
    out.append("### 3a. Literal duplicates (same members textually)")
    out.append("")
    if not result["sec3a"]:
        out.append("_No matches._")
        out.append("")
    else:
        for (kind, items), entries in result["sec3a"]:
            out.append(f"- **Kind:** `object-group {kind}` - **{len(items)} member(s)**")
            for lbl, nm in entries:
                out.append(f"  - Group: `{nm}` ({lbl})")
            sample = list(items)[:max_members_shown]
            for it in sample:
                out.append(f"    - `{fmt_item(it)}`")
            if len(items) > max_members_shown:
                out.append(f"    - ... {len(items) - max_members_shown} more")
        out.append("")

    # --- Section 3b
    out.append("### 3b. Effective/Resolved duplicates (different members, identical resolved content)")
    out.append("")
    if not result["sec3b"]:
        out.append("_No additional matches._")
        out.append("")
    else:
        for (kind, resolved), entries in result["sec3b"]:
            out.append(f"- **Kind:** `object-group {kind}` - resolves to **{len(resolved)} element(s)**")
            for lbl, nm in entries:
                out.append(f"  - Group: `{nm}` ({lbl})")
            for it in list(resolved)[:max_members_shown]:
                out.append(f"    - `{fmt_item(it)}`")
            if len(resolved) > max_members_shown:
                out.append(f"    - ... {len(resolved) - max_members_shown} more")
        out.append("")

    # --- Summary
    out.append("## Summary")
    out.append("")
    for label, c in result["counts"].items():
        out.append(f"- `{label}`: {c['networks']} network objects, "
                   f"{c['services']} service objects, {c['groups']} object-groups")
    out.append("")
    out.append(f"- Identical network object contents: **{len(result['sec1'])}**")
    out.append(f"- Identical service object contents: **{len(result['sec2'])}**")
    out.append(f"- Literal object-group duplicates: **{len(result['sec3a'])}**")
    out.append(f"- Resolved-only object-group duplicates: **{len(result['sec3b'])}**")
    out.append("")
    return "\n".join(out)


def render_json(result: Dict) -> str:
    """JSON-serializable view of the result."""
    def conv_entries(entries):
        return [{"file": lbl, "name": nm} for lbl, nm in entries]

    payload = {
        "files": result["files"],
        "counts": result["counts"],
        "include_same_file": result["include_same_file"],
        "identical_network_objects": [
            {"content": fmt_net(c), "objects": conv_entries(e)}
            for c, e in result["sec1"]
        ],
        "identical_service_objects": [
            {"content": fmt_svc(c), "objects": conv_entries(e)}
            for c, e in result["sec2"]
        ],
        "literal_group_duplicates": [
            {
                "kind": kind,
                "member_count": len(items),
                "members": [fmt_item(it) for it in items],
                "groups": conv_entries(entries),
            }
            for (kind, items), entries in result["sec3a"]
        ],
        "resolved_group_duplicates": [
            {
                "kind": kind,
                "resolved_count": len(resolved),
                "resolved": [fmt_item(it) for it in resolved],
                "groups": conv_entries(entries),
            }
            for (kind, resolved), entries in result["sec3b"]
        ],
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect duplicate network/service objects and object-groups "
                    "across Cisco ASA/FTD configuration files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n"
               "  python3 fw_dedup_analyzer.py fw1.txt fw2.txt fw3.txt -o report.md\n",
    )
    parser.add_argument("configs", nargs="+", help="Two or more configuration files")
    parser.add_argument("-o", "--output", default="duplicate_analysis_report.md",
                        help="Markdown report path (default: duplicate_analysis_report.md)")
    parser.add_argument("--json", dest="json_output", default=None,
                        help="Also write a machine-readable JSON report to this path")
    parser.add_argument("--include-same-file", action="store_true",
                        help="Also report duplicates that occur only within a single file")
    parser.add_argument("--max-members", type=int, default=8,
                        help="Max member lines to show per group in the markdown report (default: 8)")
    args = parser.parse_args(argv)

    if len(args.configs) < 2:
        parser.error("at least two configuration files are required")

    for p in args.configs:
        if not os.path.isfile(p):
            parser.error(f"file not found: {p}")

    result = analyze(args.configs, include_same_file=args.include_same_file)

    md = render_markdown(result, max_members_shown=args.max_members)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"Wrote {args.output}")

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            f.write(render_json(result))
        print(f"Wrote {args.json_output}")

    print(
        f"Summary: nets={len(result['sec1'])} svcs={len(result['sec2'])} "
        f"groups_literal={len(result['sec3a'])} groups_resolved={len(result['sec3b'])}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
