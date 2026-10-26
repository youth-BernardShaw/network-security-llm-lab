"""Record hash-bound human approval only. This tool has no execution capability."""
import argparse
import json
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from guard import digest, inspect_python, VERSION

BASE = Path(__file__).resolve().parents[1]


def eligible(code, reviewer, environment, isolation_attested):
    issues = inspect_python(code)
    if not reviewer.strip():
        issues.append('missing_human_reviewer')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', environment):
        issues.append('invalid_environment_id')
    if not isolation_attested:
        issues.append('isolation_not_attested')
    return issues


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('file', type=Path)
    p.add_argument('--reviewer', required=True)
    p.add_argument('--environment', required=True)
    p.add_argument('--attest-isolated-low-privilege', action='store_true')
    a = p.parse_args()
    source = a.file.read_bytes()
    issues = eligible(source.decode('utf-8'), a.reviewer, a.environment, a.attest_isolated_low_privilege)
    if issues:
        print(json.dumps({'status': 'not_approved', 'issues': issues, 'auto_execute': False}, ensure_ascii=False))
        raise SystemExit(2)
    now = datetime.now(timezone.utc)
    record = {'status': 'human_attestation_recorded', 'reviewer': a.reviewer,
              'environment_id': a.environment, 'source_sha256': digest(source),
              'rule_version': VERSION, 'approved_at': now.isoformat(),
              'expires_at': (now + timedelta(hours=1)).isoformat(),
              'auto_execute': False, 'execution_status': 'not_run',
              'warning': 'Attestation is not technical proof of sandbox enforcement. Recheck hash and environment before manual run.'}
    target = BASE / 'approval_log' / (now.strftime('%Y%m%dT%H%M%S%fZ') + '.json')
    target.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(str(target))


if __name__ == '__main__':
    main()
