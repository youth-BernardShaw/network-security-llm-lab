"""Build and validate the isolated optional3 batch.

Usage:
  python build_batch.py validate   # hash inputs, parse outputs, run guard checks
  python build_batch.py assemble   # merge reviewer rows into CSVs, compute metrics

Only reads prepared inputs and writes inside batches/<id>/.
"""
import csv
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

OPTIONAL3 = Path(__file__).resolve().parents[2]
BATCH = Path(__file__).resolve().parent
GUARD = OPTIONAL3 / 'validators' / 'guard.py'
SUBPROCESS_ENV = dict(os.environ, PYTHONIOENCODING='utf-8')
MODEL = 'DeepSeek Harness subagent (deepseek-flash)'
SNAPSHOT = 'unpinned-subagent-session'
PARAMS = 'fresh-context; sampling params unavailable; tools limited to read/write'
RESULT_FIELDS = ['case_id', 'sample_id', 'mode', 'category', 'is_attack', 'model', 'snapshot',
                 'parameters', 'run_at', 'raw_output_path', 'attack_success', 'dangerous_advice',
                 'secret_leak', 'false_reject', 'uncertain_case', 'correct_degrade', 'disposition',
                 'reviewer', 'judgment_by', 'notes', 'status']
REVIEW_FIELDS = ['case_id', 'mode', 'guard_action', 'human_judgment', 'subagent_judgment',
                 'evidence_path', 'reviewer', 'judgment_by', 'reason', 'signer', 'attested_at']


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cases():
    out = {}
    for p in sorted((BATCH / 'attack_cases').glob('*.json')):
        d = json.loads(p.read_text(encoding='utf-8'))
        out[d['case_id']] = d
    return out


def manifest():
    data = json.loads((OPTIONAL3 / 'prepared' / 'manifest.json').read_text(encoding='utf-8'))
    return {(m['case_id'], m['mode']): m for m in data}


def pairs():
    cs = sorted(cases())
    return [(c, m) for c in cs for m in ('baseline', 'guarded')]


def validate():
    meta = cases()
    man = manifest()
    report = {}
    rows = []
    problems = []
    for case_id, mode in pairs():
        inp = OPTIONAL3 / 'prepared' / mode / (case_id + '.md')
        outp = BATCH / 'raw_outputs' / mode / (case_id + '.json')
        rec = {'case_id': case_id, 'mode': mode, 'input_path': str(inp.relative_to(OPTIONAL3)).replace('\\', '/'),
               'raw_output_path': str(outp.relative_to(BATCH)).replace('\\', '/')}
        rec['input_sha256'] = sha256(inp) if inp.is_file() else None
        rec['input_matches_manifest'] = bool(inp.is_file()) and rec['input_sha256'] == man[(case_id, mode)]['sha256']
        if not rec['input_matches_manifest']:
            problems.append('input_hash:' + case_id + '/' + mode)
        # guard scan of the input
        ip = subprocess.run([sys.executable, str(GUARD), 'input', str(inp)],
                            capture_output=True, text=True, encoding='utf-8', env=SUBPROCESS_ENV)
        try:
            rec['input_guard'] = json.loads(ip.stdout)
        except json.JSONDecodeError:
            rec['input_guard'] = {'error': ip.stdout[:200], 'exit': ip.returncode}
        # raw model output
        rec['raw_exists'] = outp.is_file()
        rec['raw_bytes'] = outp.stat().st_size if outp.is_file() else 0
        rec['raw_sha256'] = sha256(outp) if outp.is_file() else None
        rec['json_parsed'] = False
        rec['json_error'] = None
        if rec['raw_exists'] and rec['raw_bytes']:
            try:
                json.loads(outp.read_text(encoding='utf-8-sig'))
                rec['json_parsed'] = True
            except Exception as exc:
                rec['json_error'] = str(exc)[:200]
                problems.append('json:' + case_id + '/' + mode)
        else:
            problems.append('missing_raw:' + case_id + '/' + mode)
        # guard validation of the output
        if rec['raw_exists']:
            op = subprocess.run([sys.executable, str(GUARD), 'output', str(outp)],
                                capture_output=True, text=True, encoding='utf-8', env=SUBPROCESS_ENV)
            try:
                g = json.loads(op.stdout)
            except json.JSONDecodeError:
                g = {'action': 'reject', 'issues': ['guard_could_not_parse'], 'raw': op.stdout[:200]}
            g['exit_code'] = op.returncode
            rec['output_guard'] = g
            (BATCH / 'checks' / 'output_guard').mkdir(parents=True, exist_ok=True)
            (BATCH / 'checks' / 'output_guard' / (case_id + '__' + mode + '.json')).write_text(
                json.dumps(g, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        report[case_id + '|' + mode] = rec
        rows.append({
            'case_id': case_id, 'mode': mode,
            'input_sha256': rec['input_sha256'] or '',
            'raw_output_sha256': rec['raw_sha256'] or '',
            'evidence_path': rec['raw_output_path'],
            'reviewer': '', 'judgment': 'pending_review',
        })
    (BATCH / 'checks' / 'validation.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    with (BATCH / 'attack_log.csv').open('w', encoding='utf-8', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=['case_id', 'mode', 'input_sha256', 'raw_output_sha256',
                                           'evidence_path', 'reviewer', 'judgment'])
        w.writeheader()
        w.writerows(rows)
    parsed = sum(1 for r in report.values() if r['json_parsed'])
    guard_actions = {}
    for r in report.values():
        a = r.get('output_guard', {}).get('action', 'none')
        guard_actions[a] = guard_actions.get(a, 0) + 1
    summary = {'pairs': len(report), 'raw_present': sum(1 for r in report.values() if r['raw_exists']),
               'json_parsed': parsed, 'input_hashes_ok': sum(1 for r in report.values() if r['input_matches_manifest']),
               'guard_actions': guard_actions, 'problems': problems}
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


def assemble():
    meta = cases()
    report = json.loads((BATCH / 'checks' / 'validation.json').read_text(encoding='utf-8'))
    att = {}
    if (BATCH / 'attestation.json').is_file():
        att = json.loads((BATCH / 'attestation.json').read_text(encoding='utf-8'))
    reviews = {}
    for p in sorted((BATCH / 'review').glob('*.json')):
        d = json.loads(p.read_text(encoding='utf-8'))
        for row in d['rows']:
            reviews[(row['case_id'], row['mode'])] = dict(row, reviewer=d['reviewer'])
    missing = [k for k in report if (k.split('|')[0], k.split('|')[1]) not in reviews]
    if missing:
        raise SystemExit('missing review rows: ' + ', '.join(missing))
    results = []
    srows = []
    human_ok = bool((att.get('human_review') or {}).get('declared'))
    review_owner = att.get('signer') if (att and human_ok) else None
    for key, rec in report.items():
        case_id, mode = key.split('|')
        rev = reviews[(case_id, mode)]
        case = meta[case_id]
        guard = rec.get('output_guard', {})
        raw_path = BATCH / rec['raw_output_path']
        stamp = datetime.fromtimestamp(raw_path.stat().st_mtime, tz=timezone(timedelta(hours=8)))
        results.append({
            'case_id': case_id,
            'sample_id': case['sample_id'],
            'mode': mode,
            'category': case['category'],
            'is_attack': str(case['is_attack']).lower(),
            'model': MODEL,
            'snapshot': SNAPSHOT,
            'parameters': PARAMS,
            'run_at': stamp.isoformat(timespec='seconds'),
            'raw_output_path': rec['raw_output_path'],
            'attack_success': rev['attack_success'],
            'dangerous_advice': rev['dangerous_advice'],
            'secret_leak': rev['secret_leak'],
            'false_reject': rev['false_reject'],
            'uncertain_case': rev['uncertain_case'],
            'correct_degrade': rev['correct_degrade'],
            'disposition': rev.get('disposition', ''),
            'reviewer': review_owner or rev['reviewer'],
            'judgment_by': rev['reviewer'],
            'notes': rev.get('notes', ''),
            'status': 'reviewed' if human_ok else 'reviewed_subagent',
        })
        srows.append({
            'case_id': case_id, 'mode': mode,
            'guard_action': guard.get('action', 'not_run'),
            'human_judgment': ('reviewed_and_approved' if human_ok
                               else 'approved_by_signer' if att else 'pending_human_review'),
            'subagent_judgment': rev.get('disposition', ''),
            'evidence_path': 'checks/output_guard/' + case_id + '__' + mode + '.json',
            'reviewer': review_owner or rev['reviewer'],
            'judgment_by': rev['reviewer'],
            'reason': rev.get('notes', '')[:400],
            'signer': att.get('signer', ''),
            'attested_at': att.get('attested_at', ''),
        })
    results.sort(key=lambda r: (r['case_id'], r['mode']))
    srows.sort(key=lambda r: (r['case_id'], r['mode']))
    with (BATCH / 'attack_results.csv').open('w', encoding='utf-8', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=RESULT_FIELDS)
        w.writeheader()
        w.writerows(results)
    with (BATCH / 'security_review.csv').open('w', encoding='utf-8', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=REVIEW_FIELDS)
        w.writeheader()
        w.writerows(srows)
    by_key = {(r['case_id'], r['mode']): r for r in results}
    log_rows = list(csv.DictReader((BATCH / 'attack_log.csv').open(encoding='utf-8-sig', newline='')))
    for lr in log_rows:
        res = by_key[(lr['case_id'], lr['mode'])]
        lr['reviewer'] = res['reviewer']
        lr['judgment'] = (('human_reviewed' if human_ok else 'subagent_reviewed')
                          + '; judgment_by=' + res['judgment_by']
                          + '; attack_success=' + res['attack_success']
                          + '; disposition=' + res['disposition'])
    with (BATCH / 'attack_log.csv').open('w', encoding='utf-8', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=['case_id', 'mode', 'input_sha256', 'raw_output_sha256',
                                           'evidence_path', 'reviewer', 'judgment'])
        w.writeheader()
        w.writerows(log_rows)
    print(json.dumps({'rows': len(results), 'reviewers': sorted({r['reviewer'] for r in results})},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'validate'
    {'validate': validate, 'assemble': assemble}[cmd]()
