# Default YARA rules

`meles.yar` holds the YARA rules meles ships by default. clamd runs them with
ClamAV's own YARA support; the chart serves them from the database mirror and
freshclam loads them into every clamd pod (see `yara` in `values.yaml`).

The rules are not part of meles' own code and are not under its Apache-2.0
license: every rule keeps the license of its source (table below, license
texts in [`LICENSES/`](LICENSES)). Each rule's `meta` block names its
`author`, the original rule (`source_url`) and the license (`license_url`).

## Selection

Taken from the [YARA Forge](https://yarahq.github.io/) package 20261018
(core set, plus 11 cryptominer rules from the full set). A rule is included
only if

- its source has a license that allows redistribution (sources without one,
  GPL and Elastic License sources are left out),
- it is about threats in containers: cryptominers (10 rules), Linux malware
  (78), webshells (48) and attacks on Docker and Kubernetes (5),
- it loads in ClamAV 1.4 (no modules, no `global` rules) and compiles in
  [YARA-X](https://virustotal.github.io/yara-x/), so that a later switch of
  the engine needs no rewrite,
- it caused no false positives: the set was scanned against 63 images of a
  typical cluster (Debian, Alpine, Go, Java, Node, Python and PHP based) with
  no YARA finding; an XMRig config file was detected.

Windows-only rules were dropped. The only change to the rules: meta values
that are empty strings are removed, ClamAV's parser rejects them.

## Sources and licenses

| Source | Rules | License |
|---|---:|---|
| [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) (Florian Roth, Nextron Systems, and others) | 81 | [Detection Rule License 1.1](LICENSES/DRL-1.1.txt) |
| [volexity/threat-intel](https://github.com/volexity/threat-intel) | 18 | [BSD-2-Clause](LICENSES/BSD-2-Clause-volexity_threat-intel.txt) |
| [ditekshen/detection](https://github.com/ditekshen/detection) | 17 | [BSD-2-Clause](LICENSES/BSD-2-Clause-ditekshen_detection.txt) |
| [SEKOIA-IO/Community](https://github.com/SEKOIA-IO/Community) | 13 | [Detection Rule License 1.1](LICENSES/DRL-1.1.txt) |
| [advanced-threat-research/Yara-Rules](https://github.com/advanced-threat-research/Yara-Rules) (Trellix ARC) | 8 | [Apache-2.0](LICENSES/Apache-2.0.txt) |
| [mandiant/red_team_tool_countermeasures](https://github.com/mandiant/red_team_tool_countermeasures) | 2 | [BSD-2-Clause](LICENSES/BSD-2-Clause-mandiant_red_team_tool_countermeasures.txt) |
| [WithSecureLabs/iocs](https://github.com/WithSecureLabs/iocs) | 1 | [BSD-2-Clause](LICENSES/BSD-2-Clause-WithSecureLabs_iocs.txt) |
| [eset/malware-ioc](https://github.com/eset/malware-ioc) | 1 | [BSD-2-Clause](LICENSES/BSD-2-Clause-eset_malware-ioc.txt) |

The Detection Rule License requires the rule author in every message about
a match. meles therefore embeds an index of these rules (rule → author,
license, source; `internal/yararules`) and adds it to every finding: the CLI
table and JSON, MalwareReports, the web UI, the CSV export and Harbor
reports.

## Changing the rules

1. Edit `meles.yar`. A new rule needs `author`, `source_url` and a
   `license_url` of a source in the table above (add the source to the
   table, to `LICENSES/` and to `hack/yaraindex/main.go` otherwise).
2. `go generate ./internal/yararules` updates the embedded index.
3. CI checks that ClamAV loads every rule (`clamscan` counts one signature
   per rule and reports no parse error), that YARA-X compiles the file and
   that the index is current.
