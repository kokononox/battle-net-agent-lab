"""Safe v2 SQLite diagnostics and realistic-order work-cache regression tests."""
from pathlib import Path
from unittest.mock import patch
import io,json,sqlite3,tempfile,unittest
import saved_object_review as o
import source_binding as b
from test_saved_object_review import Integration as Base,raw_manifest,selected

def sql_error(code=sqlite3.SQLITE_IOERR,name='SQLITE_IOERR'):
    ex=sqlite3.OperationalError('PRIVATE_FILE_PATH secret EKey SQL must never appear')
    ex.sqlite_errorcode=code;ex.sqlite_errorname=name;return ex

class Diagnostics(unittest.TestCase):
    def error(self,ex=None):return o.DatabaseStop('object_private_or_readonly_database_stopped_safely',ex or sql_error(),'deduplicate_selected_records',302.9,{'completed_manifest_records':4096,'completed_selected_records':2000})
    def test_numeric_sqlite_diagnostics_without_message(self):
        q=o.public_error(self.error(),'remove_private_workspace');self.assertEqual(q['sqlite_errorcode'],sqlite3.SQLITE_IOERR);self.assertEqual(q['sqlite_errorname'],'SQLITE_IOERR');self.assertEqual(q['stage'],'deduplicate_selected_records');self.assertEqual(q['elapsed_seconds'],302);self.assertNotIn('PRIVATE',json.dumps(q));self.assertNotIn('secret',json.dumps(q))
    def test_unknown_name_redacted(self):
        q=o.public_error(self.error(sql_error(10,'SQLITE_PRIVATE_SECRET')));self.assertNotIn('sqlite_errorname',q);self.assertNotIn('SECRET',json.dumps(q))
    def test_mismatched_name_code_not_published(self):
        q=o.public_error(self.error(sql_error(sqlite3.SQLITE_FULL,'SQLITE_IOERR')));self.assertEqual(q['sqlite_errorcode'],sqlite3.SQLITE_FULL);self.assertNotIn('sqlite_errorname',q)
    def test_no_code_when_python_has_no_sqlite_attributes(self):
        q=o.public_error(self.error(sqlite3.OperationalError('PRIVATE_PATH')));self.assertNotIn('sqlite_errorcode',q);self.assertNotIn('PRIVATE',json.dumps(q))
    def test_private_work_removed_flag_requires_true(self):
        ex=self.error();self.assertFalse(o.public_error(ex)['private_work_removed']);ex.private_work_removed=True;self.assertTrue(o.public_error(ex)['private_work_removed'])
    def test_completed_counts_only_not_keys_or_file_positions(self):
        q=o.public_error(self.error());self.assertEqual(q['completed_manifest_records'],4096);self.assertEqual(q['completed_selected_records'],2000);self.assertNotIn('ekeys',q);self.assertNotIn('sql',q)
    def test_bounded_work_cache_and_db_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=o.open_work(Path(tmp)/'work.sqlite',lambda:None)
            try:
                self.assertEqual(db.execute('PRAGMA main.cache_size').fetchone()[0],-65536)
                self.assertEqual(db.execute('PRAGMA main.max_page_count').fetchone()[0]*4096,512*1024**2)
            finally:db.close()
    def test_collect_completion_telemetry_and_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=o.open_work(Path(tmp)/'work.sqlite',lambda:None)
            try:
                raw=raw_manifest();sel,_=selected(raw);stats={};q,r=o.collect(db,io.BytesIO(raw),len(raw),sel,lambda:None,_telemetry=stats)
                self.assertEqual(stats,{'completed_manifest_records':8,'completed_selected_records':4});self.assertEqual(q['unique_ekeys'],3)
            finally:db.close()
    def test_legacy_errors_still_safe(self):
        q=o.public_error(b.BindingError('original_safe_constant'),'join_saved_inventory');self.assertEqual(q['code'],'original_safe_constant');self.assertEqual(q['stage'],'join_saved_inventory')

class FailureIntegration(unittest.TestCase):
    setUpClass=classmethod(Base.setUpClass.__func__)
    setUp=Base.setUp;tearDown=Base.tearDown;rebind_test_manifest=Base.rebind_test_manifest
    prepare=Base.prepare;execute=Base.execute;assert_no_work=Base.assert_no_work
    def fail(self,code=sqlite3.SQLITE_FULL,name='SQLITE_FULL',cancel=None):
        model=self.prepare();events=[]
        def collect(*args,**kwargs):
            kwargs['progress']('deduplicate_selected_records')
            kwargs['_telemetry'].update(completed_manifest_records=8192,completed_selected_records=4000)
            raise sql_error(code,name)
        with patch.object(o,'collect',side_effect=collect):
            with self.assertRaises(o.DatabaseStop) as ctx:self.execute(model,progress=events.append,cancel=cancel or (lambda:False))
        self.assert_no_work();self.assertFalse((self.root/'new/Report').exists())
        return ctx.exception,events
    def test_disk_full_preserves_failure_stage_after_cleanup(self):
        ex,events=self.fail();q=o.public_error(ex,events[-1]);self.assertEqual(q['stage'],'deduplicate_selected_records');self.assertEqual(q['sqlite_errorname'],'SQLITE_FULL');self.assertTrue(q['private_work_removed']);self.assertNotIn('remove_private_workspace',events);self.assertEqual(q['completed_selected_records'],4000)
    def test_io_error_not_guessed_as_timeout(self):
        ex,_=self.fail(sqlite3.SQLITE_IOERR,'SQLITE_IOERR');self.assertEqual(str(ex),'object_private_or_readonly_database_stopped_safely');self.assertEqual(ex.sqlite_errorcode,sqlite3.SQLITE_IOERR)
    def test_generic_sql_failure_not_labeled_corruption_or_missing(self):
        ex,_=self.fail();q=o.public_error(ex);self.assertFalse(q['installation_ready']);self.assertTrue(q['unknown_is_not_missing_or_corrupt']);self.assertNotIn('PRIVATE',json.dumps(q))
    def test_sql_interrupt_due_to_time_limit_distinguished(self):
        model=self.prepare()
        def collect(*args,**kwargs):o.TIME_LIMIT=-1;raise sql_error(sqlite3.SQLITE_INTERRUPT,'SQLITE_INTERRUPT')
        with patch.object(o,'TIME_LIMIT',600),patch.object(o,'collect',side_effect=collect):
            with self.assertRaises(o.DatabaseStop) as ctx:self.execute(model)
        self.assertEqual(str(ctx.exception),'object_time_limit_during_database_work');self.assert_no_work()
    def test_sql_interrupt_due_to_cancel_distinguished(self):
        model=self.prepare();stop=[False]
        def collect(*args,**kwargs):stop[0]=True;raise sql_error(sqlite3.SQLITE_INTERRUPT,'SQLITE_INTERRUPT')
        with patch.object(o,'collect',side_effect=collect):
            with self.assertRaises(o.DatabaseStop) as ctx:self.execute(model,cancel=lambda:stop[0])
        self.assertEqual(str(ctx.exception),'object_cancelled_during_database_work');self.assert_no_work()
    def test_non_sql_failure_stage_not_overwritten_by_cleanup(self):
        model=self.prepare();progress=o.Progress()
        def collect(*args,**kwargs):kwargs['progress']('deduplicate_selected_records');raise b.BindingError('synthetic_safe_stop')
        with patch.object(o,'collect',side_effect=collect):
            with self.assertRaisesRegex(b.BindingError,'synthetic_safe_stop'):self.execute(model,progress=progress.mark)
        self.assertEqual(progress.stage,'deduplicate_selected_records');self.assert_no_work()
    def test_join_sql_failure_has_correct_stage(self):
        model=self.prepare();progress=o.Progress()
        def join(*args,**kwargs):kwargs['progress']('join_saved_inventory');raise sql_error(sqlite3.SQLITE_READONLY,'SQLITE_READONLY')
        with patch.object(o,'join_inventory',side_effect=join):
            with self.assertRaises(o.DatabaseStop) as ctx:self.execute(model,progress=progress.mark)
        q=o.public_error(ctx.exception,progress.stage);self.assertEqual(q['stage'],'join_saved_inventory');self.assertEqual(q['sqlite_errorname'],'SQLITE_READONLY');self.assert_no_work()

del Base
