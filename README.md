# Firewall Config Duplicate Object Analyzer

A small, dependency-free Python tool that scans two or more Cisco ASA / FTD
firewall configuration files and reports **network objects, service objects,
and object-groups that contain identical or redundant content** — across
files and, optionally, within a single file.

Useful for:

- Pre-migration cleanup before an FMC / cdFMC consolidation.
- Identifying naming inconsistencies (`obj_tcp_443` vs `SVC_https`).
- Finding object-groups that look different but resolve to the same IP/port set.
- Producing an auditable Markdown + JSON report for change reviews.

---

## What it detects

Matching rules:

1. **Literal object duplicates** — different `object network` / `object service`
   names that resolve to the same host / subnet / range / fqdn or
   protocol+port. Well-known ASA names are normalized to numeric ports
   (e.g. `https` ⇔ `443`, `domain` ⇔ `53`).
2. **Literal group duplicates** — different `object-group` names whose direct
   members are identical (order-insensitive).
3. **Effective / resolved group duplicates** — groups whose recursively
   expanded set of leaf elements (hosts, subnets, ports) is identical, even
   when the literal members differ.

---

## Requirements

- Python **3.7+**
- No third-party packages — pure standard library
- Runs fully offline; no data leaves your machine

---

## Quick start

```bash
# Two files
python3 fw_dedup_analyzer.py fw1.txt fw2.txt -o report.md

# A whole folder of configs
python3 fw_dedup_analyzer.py cfgs/*.txt -o fleet_report.md --json fleet_report.json
```

---

## Command-line reference

```
python3 fw_dedup_analyzer.py <config1> <config2> [<config3> ...] [options]
```

| Flag | Default | Description |
|---|---|---|
| `-o, --output PATH` | `duplicate_analysis_report.md` | Markdown report path |
| `--json PATH` | _(off)_ | Also emit a machine-readable JSON report |
| `--include-same-file` | _(off)_ | Also report duplicates within a single file |
| `--max-members N` | `8` | Max member lines shown per group block in the Markdown |
| `-h, --help` | — | Show full help |

### Examples

```bash
# All firewalls in a folder, full member listings, JSON sidecar
python3 fw_dedup_analyzer.py cfgs/*.txt \
    -o fleet_report.md \
    --json fleet_report.json \
    --max-members 200

# Surface intra-file duplicates too
python3 fw_dedup_analyzer.py cfgs/*.txt --include-same-file -o fleet_report.md

# Windows
python fw_dedup_analyzer.py cfgs\fw1.txt cfgs\fw2.txt -o report.md
```

---

## Input format

Plain text running config from ASA or FTD (e.g. `show running-config` output,
or an FMC export rendered in ASA syntax). The script only parses these
stanzas — everything else (ACLs, NAT, routing, interfaces) is ignored:

- `object network <name>` → `host` / `subnet` / `range` / `fqdn`
- `object service <name>` → `service <proto> ...`
- `object-group network|service|protocol|icmp-type <name>` with
  `network-object`, `service-object`, `port-object`, `protocol-object`,
  `icmp-object`, `group-object`

---

## Output structure

The Markdown report has four sections:

1. **Identical Network Objects** — same host / subnet / range / fqdn.
2. **Identical Service Objects** — same protocol + port footprint.
3. **Object-Group duplicates**
   - *3a. Literal* — same member list, order-insensitive.
   - *3b. Resolved* — different literal members, identical resolved leaves.
4. **Summary** — per-file object counts and totals.

Each entry shows the source file label (derived from the file's basename) so
duplicates can be traced back to the device they came from.

---

## Privacy / security

- No network calls, no telemetry, no third-party libraries.
- Inputs and outputs stay on the local filesystem.
- If you publish sample configs, **sanitize first** — scrub real public IPs,
  internal hostnames, and FQDNs as required by your organization's policy.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `at least two configuration files are required` | Pass two or more paths. |
| `file not found` | Check the path; quote it if it contains spaces. |
| Report is huge | Raise `--max-members` only when needed, or use the JSON sidecar. |
| Duplicate file basenames | The script auto-suffixes labels (`#2`, `#3`); rename inputs for cleaner labels. |
| A group you expected to match isn't grouped | Confirm both sides use the same stanza kind (`network` vs `service`) and that referenced child objects/groups exist in the same file. |

---

## License

Provided as-is. Add a license of your choice (e.g. MIT) before sharing publicly.
