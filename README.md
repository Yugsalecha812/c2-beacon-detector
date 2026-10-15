<div align="center">

```
   \_\_\_ \_\_\_\_    \_\_\_\_       \_            \_
  / \_\_\\\_\_\_ \\  |  \_ \\  \_\_\_| |\_ \_\_\_  \_\_\_| |\_
 / /    \_\_) | | | | |/ \_ \\ \_\_/ \_ \\/ \_\_| \_\_|
/ /\_\_\_ / \_\_/  | |\_| |  \_\_/ ||  \_\_/ (\_\_| |\_
\\\_\_\_\_/|\_\_\_\_\_| |\_\_\_\_/ \\\_\_\_|\\\_\_\\\_\_\_|\\\_\_\_|\\\_\_|
```

**A statistical C2 beacon detector — flags periodic, low-jitter connection patterns in network logs that are characteristic of malware check-in traffic, without inspecting any payload content.**

[!\[Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[!\[License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[!\[Dependencies](https://img.shields.io/badge/dependencies-none%20(stdlib%20only)-brightgreen.svg)](#)

</div>

\---

## Table of Contents

* [Overview](#overview)
* [Why timing, not payload](#why-timing-not-payload)
* [Installation](#installation)
* [Usage](#usage)
* [Input formats](#input-formats)
* [Examples](#examples)
* [How the detection works](#how-the-detection-works)
* [Output format](#output-format)
* [Known limitations](#known-limitations)
* [MITRE ATT\&CK context](#mitre-attck-context)
* [License](#license)

## Overview

**C2 Detect** analyzes network connection logs — either a generic CSV or
a Zeek/Bro `conn.log` — and flags source/destination pairs whose
connections occur at suspiciously regular intervals. This is a
well-established detection engineering technique: most command-and-control
frameworks "check in" to their server on a fixed interval (often with a
small randomized jitter to look less mechanical), and that regularity is
statistically distinguishable from normal human-driven or bursty
application traffic even when the payload itself is fully encrypted.

## Why timing, not payload

Modern C2 traffic is almost always encrypted (HTTPS, DNS-over-HTTPS,
etc.), so payload inspection alone won't reveal much. What's much harder
for malware to hide is the *rhythm* of its communication — a beacon that
calls home every 60 seconds ± a few seconds of jitter still produces a
measurably regular pattern, because the jitter is deliberately kept small
(too much randomness and the malware would be slow to receive commands).
This tool exploits exactly that trade-off.

## Installation

```bash
git clone https://github.com/jaloliddin-sec/c2-detect.git
cd c2-detect
```

No external dependencies — pure Python 3.9+ standard library.

## Usage

```
usage: c2\_detect.py \[-h] -f FILE \[--format {csv,zeek}]
                     \[--min-connections MIN\_CONNECTIONS]
                     \[--cov-threshold COV\_THRESHOLD] \[-o OUTPUT]

  -f, --file             Path to connection log (CSV or Zeek conn.log)
  --format               Input format: csv (default) or zeek
  --min-connections      Minimum connections per src/dst/port group to consider (default: 5)
  --cov-threshold        Max coefficient of variation to flag as beaconing (default: 0.30)
  -o, --output           Save results as JSON
```

## Input formats

**Generic CSV** — one row per connection:

```csv
timestamp,src\_ip,dst\_ip,dst\_port,duration,bytes\_sent
1700000060.0,10.0.0.15,185.220.101.42,443,0.4,220
1700000120.5,10.0.0.15,185.220.101.42,443,0.4,215
```

`timestamp` accepts either a Unix epoch or an ISO 8601 string.

**Zeek/Bro `conn.log`** — the standard tab-separated Zeek connection log,
parsed directly using its `#fields` header line. No pre-processing needed;
point the tool at the raw log file.

## Examples

**Analyze a Zeek connection log:**

```bash
python3 c2\_detect.py -f conn.log --format zeek -o beacons.json
```

**Analyze a generic CSV export from another tool/SIEM, with a stricter threshold:**

```bash
python3 c2\_detect.py -f connections.csv --cov-threshold 0.15 --min-connections 10
```

**Sample output** (from the included synthetic test data — one simulated
beacon every \~60s alongside normal browsing traffic):

```
======================================================================
            C2 BEACON DETECTION REPORT
======================================================================
Total connections analyzed : 63
Unique src/dst/port groups : 3
Suspected beacons found    : 1
----------------------------------------------------------------------
\[HIGH  ] 10.0.0.15 -> 185.220.101.42:443  (30 conns, interval=60.0s +/-3.3%)
======================================================================
```

The 30 randomly-timed "browsing" connections in the same test set and the
low-volume DNS group below the `--min-connections` threshold were both
correctly excluded — see `sample\_connections.csv` in this repo to
reproduce.

## How the detection works

1. Connections are grouped by `(src\_ip, dst\_ip, dst\_port)`.
2. For each group with at least `--min-connections` entries, the
inter-arrival intervals between consecutive connections are computed.
3. The **coefficient of variation** (`CoV = stdev / mean`) of those
intervals is calculated. Low CoV means the timing is tightly regular;
high CoV means it's irregular (human browsing, bursty app traffic).
4. Any group with `CoV <= --cov-threshold` (default `0.30`, i.e. timing
varies by 30% or less around the mean) is flagged as a suspected
beacon.
5. A secondary check on payload size consistency (`byte\_coefficient\_of\_variation`)
and the total connection count raises or lowers the confidence label
(`LOW` / `MEDIUM` / `HIGH`) — scripted C2 check-ins tend to send
near-identical payload sizes each time, on top of regular timing.

## Output format

```json
{
  "generated": "2026-07-28T12:00:00+00:00",
  "beacon\_count": 1,
  "beacons": \[
    {
      "connection\_count": 30,
      "mean\_interval\_seconds": 60.0,
      "interval\_stdev\_seconds": 1.97,
      "interval\_coefficient\_of\_variation": 0.0328,
      "mean\_bytes\_sent": 228.3,
      "byte\_coefficient\_of\_variation": 0.0891,
      "is\_beacon": true,
      "confidence": "HIGH",
      "src\_ip": "10.0.0.15",
      "dst\_ip": "185.220.101.42",
      "dst\_port": "443",
      "first\_seen": "2023-11-14T22:15:00+00:00",
      "last\_seen": "2023-11-14T22:44:07+00:00"
    }
  ]
}
```

## Known limitations

Documented deliberately rather than glossed over:

* **Jitter-heavy or long-period C2 will evade the default threshold.**
Sophisticated C2 frameworks (e.g. those using randomized sleep with
wide jitter, or check-in intervals of many hours) can push their CoV
above `0.30` on purpose specifically to evade this kind of detection.
Lowering `--cov-threshold` catches tighter beacons but increases false
negatives on high-jitter ones — there's no single threshold that
catches everything; this needs to be tuned against real traffic.
* **No protocol or content awareness.** This tool only looks at timing
and byte-count metadata — it has no idea if a "beacon" is malicious
C2, a legitimate health-check/heartbeat service, or a monitoring agent
polling on a fixed interval. All three produce the same statistical
signature. Every flagged result needs analyst triage, not automatic
blocking.
* **Domain fronting and IP rotation aren't handled.** If a C2 channel
rotates destination IPs or uses domain fronting, connections won't
group under a single `(src, dst, port)` key and the beacon pattern
will be invisible to this tool as written — that would require
grouping by SNI/hostname instead of raw destination IP, which isn't
implemented here.
* **`min\_connections` creates a detection lag.** A beacon needs at least
5 (default) observed connections before it can be flagged, meaning on
a 60-second interval there's roughly a 5-minute window before this
tool would surface it, even in ideal conditions.

## MITRE ATT\&CK context

Beaconing detection is relevant to the **Command and Control** tactic
([TA0011](https://attack.mitre.org/tactics/TA0011/)) broadly, and
specifically to techniques like:

|Technique|Relevance|
|-|-|
|[T1071](https://attack.mitre.org/techniques/T1071/) — Application Layer Protocol|Beacons commonly ride over HTTP/HTTPS/DNS to blend in|
|[T1008](https://attack.mitre.org/techniques/T1008/) — Fallback Channels|Multiple regular beacon destinations for the same host can indicate fallback C2 infrastructure|
|[T1571](https://attack.mitre.org/techniques/T1571/) — Non-Standard Port|Combine this tool's output with port context to flag beacons on unusual ports|

See the companion [siem-detection-lab](https://github.com/jaloliddin-sec/siem-detection-lab)
for signature-based detection rules, and
[Log-Analyzer](https://github.com/jaloliddin-sec/Log-Analyzer) for
pattern-based log scanning — this tool complements both by adding a
statistical, timing-based detection layer that neither of those covers.

## License

MIT — see [LICENSE](LICENSE).







\## Improvements in this fork



\- Added clearer error messages for invalid CSV timestamps, including the CSV row number.

\- Added an automated test for invalid timestamp handling.

\- Verified that all five automated tests pass and that the sample detector output remains unchanged.



\## Testing



Run the automated tests with:



```bash

python -m unittest -v

```



Run the detector against the included sample dataset with:



```bash

python c2\_detect.py -f sample\_connections.csv

```



\## Attribution



This project is based on the original work by

\[jaloliddin-sec/c2-detect](https://github.com/jaloliddin-sec/c2-detect).

The original license and copyright notice are retained.



