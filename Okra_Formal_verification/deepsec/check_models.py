#!/usr/bin/env python3
"""Run the paper model, mutation controls, and preserved parser regressions."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
DEFAULT_EXE = Path(__file__).resolve().parents[5] / "tools/deepsec/deepsec"
LISTING = BASE.parents[1] / "body/deepsec.tex"


def listing_code(text):
    match = re.search(r"\\begin\{lstlisting\}[^\n]*\n(.*?)\\end\{lstlisting\}", text, re.S)
    if not match:
        raise ValueError("No lstlisting found in body/deepsec.tex")
    return match.group(1).strip() + "\n"


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"Expected exactly one occurrence of {old!r}")
    return text.replace(old, new, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deepsec", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--check-listing", action="store_true")
    args = parser.parse_args()
    exe = args.deepsec.resolve()
    source = (BASE / "attester_unlinkability.dps").read_text()
    if args.check_listing and listing_code(LISTING.read_text()) != source:
        raise ValueError("Paper listing differs from the tested .dps model")

    # Preserve the pre-existing model once; subsequent test runs keep it intact.
    prior = BASE / "prior_listing.dps"
    if not prior.exists():
        prior.write_text(listing_code(LISTING.read_text()))

    generated = BASE / "generated"
    generated.mkdir(exist_ok=True)
    results_dir = BASE / "results" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    results_dir.mkdir(parents=True)
    query = "query trace_equiv(Left,Right)."

    identity = replace_once(source, "out(rp,(nonce0,tok0))", "out(rp,(ak0,nonce0,tok0))")
    identity = replace_once(identity, "out(rp,(nonce1,tok1))", "out(rp,(ak1,nonce1,tok1))")
    collusion = replace_once(source, "free rp.", "free rp. free audit.")
    collusion = replace_once(collusion, "| out(c,(ak,cred,nonce));", "| out(audit,(ak,cred,nonce));\n     out(c,(ak,cred,nonce));")
    direct = """let Direct =
   new sk_reg; new sk_tok;
   out(rp,(pk(sk_reg),pk(sk_tok)));
   in(rp,nonce0);
   out(rp,(nonce0,sign(hash(nonce0),sk_tok)));
   in(rp,nonce1);
   if nonce1=nonce0 then 0 else
   out(rp,(nonce1,sign(hash(nonce1),sk_tok))).
query trace_equiv(Left,Direct)."""
    stuck = """let Stuck =
   new sk_reg; new sk_tok;
   out(rp,(pk(sk_reg),pk(sk_tok)));
   in(rp,nonce0); 0.
query trace_equiv(Left,Stuck)."""
    cases = [
        ("rp_unlinkability", BASE / "attester_unlinkability.dps", "equivalent", None),
        ("identity_leak", generated / "identity_leak.dps", "not_equivalent", identity),
        ("issuance_leak", generated / "issuance_leak.dps", "not_equivalent", collusion),
        ("canonical_outputs", generated / "canonical_outputs.dps", "equivalent", replace_once(source, query, direct)),
        ("not_stuck", generated / "not_stuck.dps", "not_equivalent", replace_once(source, query, stuck)),
        ("original_submitted", BASE / "original_submitted.dps", "parser_error", None),
        ("prior_listing", prior, "parser_error", None),
        ("unsupported_unblinding", BASE / "unsupported_unblinding.dps", "parser_error", None),
    ]
    ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
    results = []
    for name, model, expected, content in cases:
        if content is not None:
            model.write_text(content)
        command = [str(exe), "--distributed", "false", "--trace", str(model)]
        started = time.monotonic()
        try:
            proc = subprocess.run(command, cwd=exe.parent, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, timeout=60)
            output = ansi.sub("", proc.stdout)
            code = proc.returncode
        except subprocess.TimeoutExpired as error:
            output = str(error)
            code = None
        elapsed = time.monotonic() - started
        if re.search(r"The two processes are not trace equivalent", output):
            observed = "not_equivalent"
        elif re.search(r"The two processes are trace equivalent", output):
            observed = "equivalent"
        elif re.search(r"syntax error|\bError\b|not subterm|already defined", output, re.I):
            observed = "parser_error"
        else:
            observed = "unknown"
        passed = observed == expected
        (results_dir / f"{name}.log").write_text(output)
        record = {"case": name, "expected": expected, "observed": observed,
                  "passed": passed, "exit_code": code, "wall_seconds": round(elapsed, 4),
                  "model": str(model), "sha256": hashlib.sha256(model.read_bytes()).hexdigest(),
                  "command": command}
        results.append(record)
        print(f"{'PASS' if passed else 'FAIL'} {name}: {observed} ({elapsed:.3f}s)", flush=True)
        if not passed:
            print(output[-2500:])
    version = subprocess.run([str(exe), "--help"], cwd=exe.parent, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
    (results_dir / "deepsec-version.txt").write_text(ansi.sub("", version))
    report = {"utc": datetime.now(timezone.utc).isoformat(), "listing_checked": args.check_listing,
              "deepsec": str(exe), "cases": results}
    (results_dir / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Results: {results_dir}")
    return 0 if all(result["passed"] for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
