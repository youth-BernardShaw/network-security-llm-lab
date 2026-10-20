"""Summarize explicitly supplied POC execution evidence without touching history."""
import argparse
import csv
import hashlib
from pathlib import Path

OUT = Path(__file__).resolve().parents[1]
ROOT = OUT.parent


def read(path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def summarize(path):
    inventory = {(r["cohort"], r["sample_id"], r["finding_id"]): r
                 for r in read(OUT / "poc_execution.csv") if r["cohort"] in ("v1", "v2", "v3")}
    observed = {}
    for row in read(path):
        key = tuple(row[k] for k in ("cohort", "sample_id", "finding_id"))
        if key not in inventory or key in observed:
            raise ValueError(f"Unknown or duplicate POC: {key}")
        if row["code_sha256"] != inventory[key]["code_sha256"]:
            raise ValueError(f"Original code hash changed: {key}")
        if row["execution_status"] not in ("not_run", "executed"):
            raise ValueError("execution_status must be not_run or executed")
        if row["execution_status"] == "not_run":
            if row.get("success"):
                raise ValueError("Unexecuted POC cannot have a success value")
            observed[key] = row
            continue
        if row.get("adaptation_level") != "original":
            raise ValueError("Adapted script results must be reported separately")
        if row.get("success") not in ("true", "false"):
            raise ValueError("Executed POC needs explicit true/false")
        if not all(row.get(k) for k in ("environment_id", "condition_key", "reviewer",
                                        "started_at", "elapsed_seconds", "command_redacted")):
            raise ValueError("Missing execution metadata")
        if float(row["elapsed_seconds"]) < 0:
            raise ValueError("Negative duration")
        ep = (ROOT / row["evidence_path"]).resolve()
        if not ep.is_relative_to(ROOT.resolve()) or not ep.is_file() or not ep.stat().st_size:
            raise ValueError("Evidence must be a nonempty file within the project")
        if row["success"] == "true" and row.get("restore_status") not in ("restored", "not_applicable"):
            raise ValueError("Successful write tests need restoration evidence")
        if row["success"] == "false" and not row.get("failure_category"):
            raise ValueError("Failure needs a category")
        observed[key] = row
    summaries = []
    for cohort in ("v1", "v2", "v3"):
        keys = [k for k in inventory if k[0] == cohort]
        done = [observed[k] for k in keys if k in observed and observed[k]["execution_status"] == "executed"]
        successes = sum(r["success"] == "true" for r in done)
        untested = len(keys) - len(done)
        summaries.append(dict(cohort=cohort, generated=len(keys), tested=len(done),
            succeeded=successes, failed=len(done)-successes, untested=untested,
            coverage=f"{len(done)/len(keys):.8f}",
            confirmed_success_lower_bound=f"{successes/len(keys):.8f}",
            possible_success_upper_bound=f"{(successes+untested)/len(keys):.8f}",
            runnable_rate=f"{successes/len(keys):.8f}" if not untested else "",
            status="complete" if not untested else "partial_not_final",
            source_results_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    target = OUT / "followup_poc_metrics.csv"
    with target.open("w", encoding="utf-8-sig", newline="") as f:
        w=csv.DictWriter(f, list(summaries[0]));w.writeheader();w.writerows(summaries)
    print(target)


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("results", type=Path)
    args=p.parse_args()
    summarize(args.results)
