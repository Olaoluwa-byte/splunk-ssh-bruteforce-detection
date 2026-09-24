#!/usr/bin/env python3
"""P1.5: load fixtures into a throwaway Splunk, run the detection, assert results."""
import base64, json, os, re, ssl, subprocess, sys, time, urllib.parse, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTAINER = os.environ.get("SPLUNK_CONTAINER", "splunk-ci")
API = os.environ.get("SPLUNK_API", "https://localhost:18089")
PW = os.environ["SPLUNK_PASSWORD"]
DETECTION = os.path.join(ROOT, "detections", "ssh_bruteforce_password_spray.spl")
PROD_INDEX = "index=linux_auth"
THRESHOLD = "| where failures >= 10"   # must match the alert's threshold line exactly

# fixture, test index, raw lines, peak weighted attempts, alert rows, (mitre, severity)
CASES = [
    ("attack_run1.log",     "t_attack",    25, 25, 1, ("T1110.003", "high")),
    ("typos_collapsed.log", "t_collapsed",  2,  3, 0, None),
    ("typos_fixed.log",     "t_fixed",      3,  3, 0, None),
]

CTX = ssl._create_unverified_context()  # throwaway container's self-signed cert only

def api(path, **data):
    req = urllib.request.Request(API + path, data=urllib.parse.urlencode(data).encode())
    tok = base64.b64encode(f"admin:{PW}".encode()).decode()
    req.add_header("Authorization", "Basic " + tok)
    with urllib.request.urlopen(req, context=CTX, timeout=120) as r:
        return r.read().decode()

def search(spl):
    spl = spl.strip()
    if not spl.startswith("|"):
        spl = "search " + spl
    body = api("/services/search/jobs/export", search=spl, output_mode="json",
               earliest_time="0", latest_time="now")
    rows = [json.loads(l) for l in body.splitlines() if l.strip()]
    return [r["result"] for r in rows if "result" in r]

def cli(*args):
    subprocess.run(["docker", "exec", "-u", "splunk", CONTAINER, "/opt/splunk/bin/splunk",
                    *args, "-auth", f"admin:{PW}"], check=True, stdout=subprocess.DEVNULL)

def ingest(fixture, index, expected):
    src = os.path.join(ROOT, "tests", "fixtures", fixture)
    subprocess.run(["docker", "cp", src, f"{CONTAINER}:/tmp/{fixture}"], check=True)
    cli("add", "index", index)
    cli("add", "oneshot", f"/tmp/{fixture}", "-index", index, "-sourcetype", "linux_secure")
    for _ in range(60):  # oneshot is async: wait until every line is indexed
        n = int(search(f"| tstats count where index={index}")[0]["count"])
        if n == expected:
            return
        time.sleep(2)
    raise AssertionError(f"{fixture}: indexed {n} events, expected {expected}")

def main():
    spl = open(DETECTION).read().strip()
    assert PROD_INDEX in spl, f"detection must reference {PROD_INDEX}"
    lines = spl.splitlines()
    norm = [re.sub(r"\s+", " ", l.strip()) for l in lines]
    assert THRESHOLD in norm, f"detection must contain the line: {THRESHOLD}"
    cut = norm.index(THRESHOLD)
    # Same logic up to the threshold, then report the peak even when it never crosses
    metrics_spl = "\n".join(lines[:cut]) + "\n| stats max(failures) AS peak_failures BY src_ip"

    failures = 0
    for fixture, index, raw, peak, alerts, labels in CASES:
        name = fixture.removesuffix(".log")
        try:
            ingest(fixture, index, raw)
            metrics = search(metrics_spl.replace(PROD_INDEX, f"index={index}"))
            rows = search(spl.replace(PROD_INDEX, f"index={index}"))
            got_peak = int(float(metrics[0]["peak_failures"])) if metrics else 0
            assert got_peak == peak, f"peak {got_peak}, expected {peak}"
            assert len(rows) == alerts, f"alert rows {len(rows)}, expected {alerts}"
            if labels:
                got = (rows[0].get("mitre"), rows[0].get("severity"))
                assert got == labels, f"mitre/severity {got}, expected {labels}"
            print(f"PASS {name}: raw={raw} peak={got_peak} alert_rows={len(rows)}"
                  + (f" mitre={labels[0]} severity={labels[1]}" if labels else ""))
        except AssertionError as e:
            failures += 1
            print(f"FAIL {name}: {e}")
    sys.exit(1 if failures else 0)

if __name__ == "__main__":
    main()
