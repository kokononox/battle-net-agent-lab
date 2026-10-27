"""Read-only, sanitized readiness report. No Apply/Restore entrypoint."""
from pathlib import Path
import json, os, re, sys, uuid
BASE = Path(__file__).resolve().parents[1]

def summarize(result):
    review = result['policy_review']
    issues = [{k: row.get(k, '') for k in ('severity', 'title', 'fix')}
              for row in review.get('issues', [])]
    errors = [row for row in issues if row['severity'] == 'error']
    code = str(result.get('technical', {}).get('preflight_error', '')).split(';', 1)[0].strip()
    if not re.fullmatch(r'[A-Za-z0-9_]*', code):
        code = 'see_local_private_job' if code else ''
    return dict(schema='hf11-integrated-readiness-1',
                mode=review['mode'], native_readiness=review['native_readiness'],
                preflight_passed=(review['native_readiness'] == 'ready_at_check_time'
                                  and review['mode'] in ('direct_isolation', 'full_isolation')
                                  and not errors),
                firewall_modified=False, applied=False, restored=False,
                packet_leak_tested=False, no_leak_certified=False,
                technical_error_code=code, issues=issues)

def run():
    report = dict(schema='hf11-integrated-readiness-1', preflight_passed=False,
                  firewall_modified=False, applied=False, restored=False,
                  packet_leak_tested=False, no_leak_certified=False)
    try:
        if os.name != 'nt':
            raise RuntimeError('Windows_required')
        sys.path.insert(0, str(BASE / 'lab'))
        from console import verify_package
        verify_package()
        from state import Store, assert_local_tree
        from policy_review import handle
        job = assert_local_tree(BASE / 'private-state/jobs' / uuid.uuid4().hex)
        job.mkdir(parents=True)
        report = summarize(handle(Store(BASE / 'private-state'), {}, job))
    except Exception as exc:
        report['readiness_error_type'] = type(exc).__name__
        # Do not export paths, addresses, usernames or unfiltered exceptions.
    path = BASE / 'HF11-PREFLIGHT.json'
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Read-only preflight passed:', report['preflight_passed'])
    print('Report: HF11-PREFLIGHT.json. No firewall Apply/Restore performed.')
    return 0 if report['preflight_passed'] else 1

if __name__ == '__main__':
    raise SystemExit(run())
