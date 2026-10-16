"""Keep failed native safety tests blocking Setup, but publish a sanitized reason."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import re
import unittest
from observe_agent import initial_report
from ui_accessibility import TOOLCHAIN_CODES

KINDS={'AssertionError','TimeoutExpired','ToolchainError','ImportError','ModuleNotFoundError','OSError','ValueError','TypeError','KeyError','RuntimeError','Other'}

def validate_summary(s):
    fields={'result','discovered','executed','skipped','failure_count','failures','failure_list_truncated'}
    if type(s) is not dict or set(s)!=fields:raise ValueError('test_summary_schema')
    for k in ('discovered','executed','skipped','failure_count'):
        if type(s[k]) is not int or not 0<=s[k]<=10000:raise ValueError('test_summary_count')
    if not 0<=s['skipped']<=s['executed']<=s['discovered']:raise ValueError('test_summary_count')
    if type(s['failure_list_truncated']) is not bool:raise ValueError('test_summary_count')
    if s['result']!=('failed' if s['failure_count'] else 'passed'):raise ValueError('test_summary_result')
    if type(s['failures']) is not list or len(s['failures'])>16 or len(s['failures'])!=min(s['failure_count'],16):raise ValueError('test_summary_failures')
    if s['failure_list_truncated']!=(s['failure_count']>16):raise ValueError('test_summary_truncated')
    for f in s['failures']:
        if type(f) is not dict or set(f)!={'test_id','error_kind','toolchain_code','compiler_codes'}:raise ValueError('test_summary_failure')
        if type(f['test_id']) is not str or not re.fullmatch(r'[A-Za-z0-9_.]{1,160}',f['test_id']):raise ValueError('test_summary_id')
        if f['error_kind'] not in KINDS:raise ValueError('test_summary_kind')
        if f['toolchain_code'] is not None and f['toolchain_code'] not in TOOLCHAIN_CODES:raise ValueError('test_summary_code')
        if type(f['compiler_codes']) is not list or len(f['compiler_codes'])>8 or any(type(c) is not str or not re.fullmatch(r'CS[0-9]{4}',c) for c in f['compiler_codes']):raise ValueError('test_summary_compiler_codes')
    return s

class SafeResult(unittest.TestResult):
    def __init__(self):super().__init__();self.safe_failures=[];self.total_failed=0
    def record(self,test,err):
        self.total_failed+=1
        if len(self.safe_failures)>=16:return
        identifier=test.id();identifier=identifier if re.fullmatch(r'[A-Za-z0-9_.]{1,160}',identifier) else 'unrecognized_test'
        kind=err[0].__name__ if err else 'AssertionError';kind=kind if kind in KINDS else 'Other'
        code=getattr(err[1],'code',None) if err else None
        self.safe_failures.append({'test_id':identifier,'error_kind':kind,'toolchain_code':code if type(code) is str and code in TOOLCHAIN_CODES else None,
            'compiler_codes':getattr(err[1],'compiler_codes',[]) if err and kind=='ToolchainError' else []})
    def addError(self,test,err):self.errors.append((test,'details_not_exported'));self.record(test,err)
    def addFailure(self,test,err):self.failures.append((test,'details_not_exported'));self.record(test,err)
    def addUnexpectedSuccess(self,test):self.unexpectedSuccesses.append(test);self.record(test,None)
    def addSubTest(self,test,subtest,err):
        if err is not None:self.addError(test,err)

def run_suite(suite,out):
    discovered=suite.countTestCases();result=SafeResult()
    # Do not put exception strings, command lines or test stdout into CI logs/artifacts.
    with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):suite.run(result)
    summary=validate_summary({'result':'failed' if result.total_failed else 'passed','discovered':discovered,'executed':result.testsRun,
        'skipped':len(result.skipped),'failure_count':result.total_failed,'failures':result.safe_failures,'failure_list_truncated':result.total_failed>16})
    out.mkdir(parents=True,exist_ok=True)
    (out/'safety-test-summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    if summary['result']=='failed':
        report=initial_report();report.update(status='stopped',phase='safety_tests',error_code='safety_test_suite_failed',safety_test_result=summary)
        (out/'agent-observation-to-share.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return summary

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,default=Path('output'));args=parser.parse_args()
    suite=unittest.defaultTestLoader.discover('tests');summary=run_suite(suite,args.output)
    print(json.dumps(summary))
    raise SystemExit(1 if summary['result']=='failed' else 0)
