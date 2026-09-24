# SSH Brute Force & Password Spray Detection in Splunk

A home-lab detection engineering project: build, test, tune, and operationalize a Splunk detection for SSH password guessing (MITRE ATT&CK T1110.001) and password spraying (T1110.003) — end to end, from raw log onboarding to a throttled, scheduled alert managed as code.

The detection itself is simple. The value of this project is what validation uncovered: **three issues that would have silently weakened the detection in production** — a time-bucketing evasion gap, a log-pipeline blind spot, and a ground-truth mismatch between the attack and the logs.

---

## TL;DR

| | Result |
|---|---|
| Detection v1 (fixed 5-min buckets) | Caught **19 of 25** attempts (**76%**); 6 fell into a second bucket below threshold |
| Detection v2 (sliding 5-min window) | Caught **25 of 25** (**100%**); fired on the 10th failure |
| Log pipeline blind spot | rsyslog collapsed repeated failures — multi-guess-per-connection attacks undercounted by up to **3×**; fixed at source and in SPL |
| False-positive test | 3 user typos → peak rolling count **2** → no alert ✅ |
| Alert | Scheduled every 5 min, per-attacker throttle (60 min), severity High — fired as expected ✅ |

---

## Lab Architecture

```
UbuntuDesk VM — Ubuntu Desktop 24.04 LTS (VirtualBox 7.2.20, 8 GB RAM, 4 vCPU)
├── Attacker:  scripts/generate_failed_logins.sh
│              └── failed SSH password logins ──► 127.0.0.1:22
├── Victim:    OpenSSH server (systemd ssh.socket)
│              └── rsyslog ──► /var/log/auth.log
└── SIEM:      Splunk Enterprise 10.4.3 (runs as non-root 'splunk' user, systemd-managed)
               ├── File monitor ──► index=linux_auth  sourcetype=linux_secure
               └── Scheduled alert (*/5) ──► Triggered Alerts (High)
```

Attacker and victim share one VM (loopback traffic only) — safe, isolated, and fully self-generated data.

---

## Detection Lifecycle

| Phase | Work performed |
|---|---|
| 1. Platform | Installed Splunk Enterprise 10.4.3 from the official `.deb`, verified download size; ran Splunk as a dedicated non-root `splunk` user; enabled systemd boot-start |
| 2. Data onboarding | Created `linux_auth` index; file monitor on `/var/log/auth.log` with `linux_secure` sourcetype; granted read access via the `adm` group (least privilege) |
| 3. Data validation | Confirmed ingestion, Splunk read access, and `_time` parsing of Ubuntu 24.04's ISO 8601 timestamps (`2026-09-23T21:30:01.387549-04:00`) |
| 4. Attack simulation | Scripted SSH password guessing across 5 usernames (mix of valid and invalid accounts) |
| 5. Detection v1 | Fixed-bucket threshold (`bin span=5m`) |
| 6. Tuning → v2 | Sliding window (`streamstats time_window=5m`) + log-repeat weighting |
| 7. Operationalize | Scheduled alert, 15-min lookback, per-`src_ip` throttle, High severity |
| 8. Validate | True-positive alert firing; false-positive typo test |
| 9. Detection-as-code | Exported `inputs.conf` and `savedsearches.conf` to version control |

---

## Attack Simulation

`scripts/generate_failed_logins.sh` makes 25 failed SSH password logins against localhost, rotating through five usernames:

| User | Exists? | Why included |
|---|---|---|
| `fakeuser` | No | Generates the `Failed password for invalid user …` format |
| `admin` | No | Among the most-guessed usernames in real brute-force telemetry |
| `root` | Yes (locked) | Top real-world target; always fails but is still logged |
| `test` | No | Common guess for forgotten test accounts |
| `yuji` | Yes | Real account — generates the valid-user log format |

Mixing valid and invalid users tests that the parser handles both log formats, and 5 distinct users per source exercises the spraying classification.

---

## Detection Logic

**Plain English:** For every failed SSH password event, count failures from the same source IP over the previous 5 minutes. If the rolling count reaches **10+**, alert. If **more than 3 usernames** were targeted, classify as **password spraying (high)**; otherwise **brute force (medium)**. Alert once per attacker per hour.

**Production version** — [`detections/v2_streamstats_sliding.spl`](detections/v2_streamstats_sliding.spl):

```spl
index=linux_auth sourcetype=linux_secure "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+) port"
| rex "message repeated (?<repeat_count>\d+) times"
| eval attempts=coalesce(repeat_count, 1)
| sort 0 _time
| streamstats time_window=5m sum(attempts) AS failures dc(user) AS distinct_users values(user) AS users BY src_ip
| where failures >= 10
| stats max(failures) AS peak_failures max(distinct_users) AS distinct_users values(users) AS users min(_time) AS threshold_crossed BY src_ip
| eval mitre=if(distinct_users>3,"T1110.003","T1110.001"),
       severity=if(distinct_users>3,"high","medium")
| convert ctime(threshold_crossed)
```

| Line | Purpose |
|---|---|
| `rex … (invalid user )?` | Extracts `user` and `src_ip` from both valid- and invalid-user log formats |
| `rex "message repeated …"` + `coalesce` | Weights rsyslog-collapsed lines by their true repeat count (see Finding 2) |
| `sort 0 _time` | Chronological order, required by `streamstats` |
| `streamstats time_window=5m … BY src_ip` | Rolling 5-minute count per source — no fixed bucket boundaries (see Finding 1) |
| `where failures >= 10` | Threshold separating attacks from user typos |
| `stats … min(_time) AS threshold_crossed` | One row per attacker; records time-to-detect |
| `eval mitre / severity` | Spraying vs. brute-force classification |

### Alert configuration ([`config/savedsearches.conf`](config/savedsearches.conf))

| Setting | Value | Rationale |
|---|---|---|
| Schedule | `*/5 * * * *` | Near-real-time without real-time search overhead |
| Time range | `-15m` → `now` | Gives `streamstats` enough history to build its trailing 5-min window |
| Trigger | Results > 0, **for each result** (`alert.digest_mode = 0`) | One alert per attacker |
| Throttle | Suppress by `src_ip` for 60 min | Overlapping 15-min windows would otherwise re-alert on the same attack; per-field throttle still alerts on a *new* attacker |
| Action | Add to Triggered Alerts, severity High | |

---

## Findings

### Finding 1 — Fixed time buckets create a detection evasion gap

The initial detection used `bin _time span=5m` with a 10-failure threshold. The 25-attempt spray straddled a bucket boundary and split **19 / 6** (21:35 and 21:40 buckets). Only 76% of attempts were counted, and the 6 in the second bucket were discarded as below threshold.

| Version | Attempts captured | Coverage | Time to detect |
|---|---|---|---|
| `bin span=5m` (fixed) | 19 / 25 | 76% | After bucket evaluation |
| `streamstats time_window=5m` (sliding) | **25 / 25** | **100%** | **21:39:28 — on the 10th failure** |

**Risk:** an attacker pacing fewer than 10 attempts per fixed bucket would never alert.
**Fix:** sliding window via `streamstats time_window`.

**Fixed buckets — only 19 attempts counted in the 21:35 bucket:**

![Fixed buckets](screenshots/02a-detection-bin.png)

**Why — the attack split 19 / 6 across a bucket boundary:**

![Bucket split](screenshots/02b-bucket-split.png)

**Sliding window — all 25 captured, threshold crossed at 21:39:28:**

![Sliding window](screenshots/02c-detection-streamstats.png)

### Finding 2 — The log pipeline silently collapsed repeated failures

During false-positive testing, 3 wrong passwords in one SSH connection produced only **2** `Failed password` lines. The third was hidden in an rsyslog summary line:

```
sshd[68113]: Failed password for yuji from 127.0.0.1 port 43322 ssh2
sshd[68113]: message repeated 2 times: [ Failed password for yuji from 127.0.0.1 port 43322 ssh2]
sshd[68113]: PAM 2 more authentication failures; ... user=yuji
```

**Root cause:** Ubuntu's rsyslog ships with `$RepeatedMsgReduction on`, merging consecutive identical lines. Identical lines occur when an attacker makes multiple guesses **within one connection** (same source port).

**Risk:** tools that make multiple guesses per connection (sshd allows up to `MaxAuthTries` = 6) would be undercounted by up to **3×** — a 25-guess attack could register as ~9 and never alert. A data-pipeline blind spot, not a logic bug.

**Fix (defense in depth):**
1. **Source:** `$RepeatedMsgReduction off` in `/etc/rsyslog.conf` → every failure logged individually (verified: 3 typos → 3 lines, same port 42918).
2. **Detection:** extract `repeat_count` and use `sum(attempts)` instead of `count`, so the detection stays correct on hosts where syslog config isn't controlled.

**Before — third failure hidden in "message repeated 2 times":**

![Before](screenshots/05a-rsyslog-before.png)

**After — `RepeatedMsgReduction off`, all 3 failures logged individually:**

![After](screenshots/05b-rsyslog-after.png)

### Finding 3 — Ground truth must come from the logs, not the attack script

The script makes 25 attempts per run, but sshd logged **25, 27, and 27** across three runs. Some attempts produced two failures ~1 second apart for the same user (e.g., `root` at 21:58:47.003 and 21:58:47.890), likely `sshpass` answering a second password prompt within the same connection.

**Lesson:** validating coverage against *assumed* attack counts would have produced wrong numbers. Coverage metrics in this README are measured against events actually logged.

---

## Validation

| Test | Method | Expected | Result |
|---|---|---|---|
| Data ingestion | `index=linux_auth "Failed password" \| stats count BY src_ip user` | 25 events, 5 users × 5 | ✅ Exact match |
| Timestamp parsing | Compare `_time` to raw ISO 8601 timestamp | Match | ✅ Match to the millisecond |
| True positive | Run attack script | Detection fires, T1110.003 / high | ✅ Peak 25, 5 users, high |
| Scheduled alert | Rerun attack, wait for scheduled run | Triggered Alert, High, per result | ✅ Fired 22:00:00 EDT |
| False positive | 3 wrong passwords, 8+ min after attack | No alert | ✅ Peak rolling count 2 |

**Data validation — 25 events, 5 users × 5, all from 127.0.0.1:**

![Raw events](screenshots/01-raw-events.png)

**False-positive test — user typos peak at 2 failures, well below threshold:**

![False positive test](screenshots/03-false-positive-test.png)

**Scheduled alert fired — High severity, per result:**

![Triggered alert](screenshots/04-triggered-alert.png)

---

## Framework Mapping

| Framework | Mapping |
|---|---|
| **MITRE ATT&CK** | T1110.001 Brute Force: Password Guessing · T1110.003 Brute Force: Password Spraying |
| **NIST SP 800-53** | AC-7 Unsuccessful Logon Attempts · AU-6 Audit Record Review, Analysis, and Reporting · SI-4 System Monitoring |
| **CIS Controls v8** | 8.2 Collect Audit Logs · 8.11 Conduct Audit Log Reviews · 13.1 Centralize Security Event Alerting |

---

## Known Limitations

| Gap | Why it evades | Planned mitigation |
|---|---|---|
| Low-and-slow (<10 attempts in any 5 min) | Never crosses threshold | Longer-window (1–24h) per-source aggregation |
| Distributed attack (many IPs, few attempts each) | Grouped by `src_ip` | Aggregate by target user across sources |
| Successful login after failures | Detection only sees failures | Correlate `Accepted password` after a failure burst (T1078) |
| Frustrated legitimate user (4 reconnects × 3 typos = 12) | Crosses threshold of 10 | Higher threshold for single-user bursts; keep 10 for spraying |
| Localhost-only attacker | Not a realistic remote source | Separate Kali attacker VM |
| Regex-based parsing | Breaks if the OpenSSH log format changes | Map to the CIM `Authentication` data model |
| Unclean VM shutdowns | Left non-text (binary) bytes in `auth.log`; Splunk's binary check could skip a file that *begins* with them | Graceful shutdowns; monitor for ingestion gaps |
| Splunk trial license | Converts to Free after 60 days, which disables alerting | Splunk Developer license |

---

## Repository Structure

```
splunk-ssh-bruteforce-detection/
├── README.md
├── config/
│   ├── inputs.conf              # File monitor: /var/log/auth.log → index=linux_auth
│   └── savedsearches.conf       # Alert definition: search, schedule, throttle, severity
├── detections/
│   ├── v1_bin_bucket.spl        # Original fixed-bucket version (kept to show the gap)
│   └── v2_streamstats_sliding.spl  # Production version
├── scripts/
│   └── generate_failed_logins.sh   # Attack simulation (T1110.001 / .003)
└── screenshots/
    ├── 01-raw-events.png
    ├── 02a-detection-bin.png
    ├── 02b-bucket-split.png
    ├── 02c-detection-streamstats.png
    ├── 03-false-positive-test.png
    ├── 04-triggered-alert.png
    ├── 05a-rsyslog-before.png
    └── 05b-rsyslog-after.png
```

---

## Reproduce It

**Prerequisites:** Ubuntu 24.04 VM (8 GB RAM recommended), Splunk Enterprise `.deb` (free trial), internet access for packages.

```bash
# 1. Install Splunk as a non-root service
sudo dpkg -i splunk-*.deb
sudo chown -R splunk:splunk /opt/splunk
sudo usermod -aG adm splunk                      # read access to /var/log/auth.log
sudo -u splunk /opt/splunk/bin/splunk start --accept-license
sudo -u splunk /opt/splunk/bin/splunk stop
sudo /opt/splunk/bin/splunk enable boot-start -systemd-managed 1 -user splunk
sudo systemctl start Splunkd

# 2. Victim service + attack tooling
sudo apt install -y openssh-server sshpass

# 3. Stop rsyslog from collapsing repeated lines (Finding 2)
sudo sed -i 's/^\$RepeatedMsgReduction on/$RepeatedMsgReduction off/' /etc/rsyslog.conf
sudo systemctl restart rsyslog

# 4. Create index 'linux_auth' in Splunk Web, then deploy config/*.conf
#    into /opt/splunk/etc/apps/<your_app>/local/ and restart Splunk

# 5. Run the attack
./scripts/generate_failed_logins.sh
```

Then run `detections/v2_streamstats_sliding.spl` over the last 15 minutes, or wait for the scheduled alert under **Activity → Triggered Alerts**.

---

## Next Steps (Project 2)

- Kali Linux VM as a remote attacker on a shared NAT Network (real external `src_ip`)
- Success-after-failure correlation (T1078 Valid Accounts)
- Per-user aggregation to catch distributed spraying
- Map to the CIM `Authentication` data model and convert to `tstats`

---

## Author

**Samson Amosu** — Security Engineer (detection engineering, Splunk ES)
[LinkedIn](https://www.linkedin.com/in/samson-amosu) · [GitHub](https://github.com/Olaoluwa-byte)

---

## P1.5 — Detection-as-code CI (v1.1)

[![detection-tests](https://github.com/Olaoluwa-byte/splunk-ssh-bruteforce-detection/actions/workflows/detection-tests.yml/badge.svg)](https://github.com/Olaoluwa-byte/splunk-ssh-bruteforce-detection/actions/workflows/detection-tests.yml)

Every push and pull request runs the detection against real attack logs in a disposable Splunk container. The build fails if detection behavior changes.

### How it works

1. GitHub Actions (`ubuntu-24.04`) starts `splunk/splunk`, pinned by digest to **Splunk 10.4.3 (build 4174a2deda5d)**, the same build as the lab instance.
2. Each fixture is loaded into its own index with `splunk add oneshot` (sourcetype `linux_secure`). The harness waits until the indexed event count equals the fixture's line count. This is a pipeline-completeness check.
3. The detection in `detections/ssh_bruteforce_password_spray.spl` runs **verbatim** (only the index is swapped) with `earliest_time=0`. A second copy, truncated at the threshold, measures peak attempts on fixtures that never alert.
4. The harness asserts peak weighted attempts, alert row count, MITRE technique, and severity.

### Test cases

| Fixture | Raw lines | Weighted attempts | Peak (5m sliding) | Alert rows | Labels |
|---|---|---|---|---|---|
| `attack_run1.log` | 25 | 25 | 25 | 1 | T1110.003 / high |
| `typos_collapsed.log` | 2 | **3** | 3 | 0 | — |
| `typos_fixed.log` | 3 | 3 | 3 | 0 | — |

### Why the collapsed-typo test matters

rsyslog's `$RepeatedMsgReduction` logged 3 failed attempts on one SSH connection as **2 lines** (`message repeated 2 times`). A plain event count reports 2. The detection weights each event with `coalesce(repeat_count, 1)` and recovers all 3. If anyone removes the weighting, this test fails. For attackers who make several guesses per connection, the undercount can reach about 3x.

The raw per-minute counts from `auth.log` also confirm the fixed-bucket evasion finding from Project 1: attack run 1 logged **19 events at 21:39 and 6 at 21:40**. A `bin span=5m` search splits the attack at 21:40 and misses the 6, while the sliding window catches all 25.

### Fixture provenance

Fixtures were extracted from `/var/log/auth.log` (ground truth), not from the attack script's intended counts, since later script runs logged 27 attempts each, not 25:

```bash
sudo zgrep -ahE "Failed password|message repeated" /var/log/auth.log* \
  | tr -d '\000' | grep 'sshd\[' | grep "<minute window>" | sort
```

- `-a` / `tr -d '\000'`: `auth.log` contained NUL bytes, most likely from an unclean VM shutdown. They make grep treat the file as binary and print no lines.
- `grep 'sshd\['`: drops `sudo` audit lines, which contain "Failed password" in the logged command line.
- Line counts were checked before committing: 25 / 2 / 3.

### Repo layout

```
detections/ssh_bruteforce_password_spray.spl   # source of truth for the saved alert
tests/fixtures/*.log                           # raw auth.log extracts
tests/start_splunk.sh                          # starts pinned Splunk container, waits for healthy
tests/run_tests.py                             # ingest, search via REST, assert
.github/workflows/detection-tests.yml          # CI
```

### Run locally

```bash
export SPLUNK_PASSWORD='<8+ chars>'
./tests/start_splunk.sh && python3 tests/run_tests.py
docker rm -f splunk-ci
```

### Operating rules

- **The repo comes first.** Change the SPL here, wait for CI to pass, then update the saved search. (The deploy is manual for now; deploying through Splunk's REST API is planned.)
- **Threshold coupling.** `THRESHOLD` in `run_tests.py` must match the `| where failures >= 10` line. If they don't match, the harness fails loudly rather than passing.
- **Version parity.** The Splunk image is pinned by digest. Bump it in the same PR as any lab Splunk upgrade.
- **MITRE labeling.** `distinct_users > 3` means T1110.003 (spraying); otherwise T1110.001. A spray against exactly 3 accounts is labeled T1110.001 / medium by design.
- **Timezones.** The container runs in UTC and the lab in EDT, so `threshold_crossed` is intentionally not asserted.

### Known limitations

- Aggregation is per `src_ip`. A spray distributed across many source IPs is not covered.
- The fixtures come from localhost (`127.0.0.1`) lab traffic.

### Framework mapping

- **MITRE ATT&CK:** T1110.001 Password Guessing, T1110.003 Password Spraying
- **NIST SP 800-53:** AC-7 (Unsuccessful Logon Attempts), SI-4 (System Monitoring), CM-3 (Configuration Change Control, i.e. detection changes gated by CI)
