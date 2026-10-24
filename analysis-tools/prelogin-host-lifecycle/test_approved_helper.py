from pathlib import Path
import tempfile,unittest
from approved_helper import allowed,HASH,PARENTS
class HelperTests(unittest.TestCase):
    def call(self,change=None):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'Battle.net'/'Agent'/'Agent.synthetic';root.mkdir(parents=True)
            kw=dict(path=root/'AgentHelper.exe',parent_path=root/'Agent.exe',parent_row=dict(process_name='agent.exe',sha256=next(iter(PARENTS)),instrumented_before_resume=True),digest=HASH,signature=dict(authenticode_valid=True,expected_blizzard_publisher=True,accepted_for_execution=True),env={'PROGRAMDATA':tmp},parent_identity_matches=True,is_reparse=lambda p:False)
            if change:change(kw)
            return allowed(**kw)
    def test_exact_policy_passes(self):self.assertTrue(self.call())
    def test_wrong_hash_fails(self):self.assertFalse(self.call(lambda k:k.update(digest='0'*64)))
    def test_other_basename_fails(self):self.assertFalse(self.call(lambda k:k.update(path=k['path'].with_name('cmd.exe'))))
    def test_untrusted_fails(self):self.assertFalse(self.call(lambda k:k['signature'].update(authenticode_valid=False)))
    def test_other_publisher_fails(self):self.assertFalse(self.call(lambda k:k['signature'].update(expected_blizzard_publisher=False)))
    def test_non_agent_parent_fails(self):self.assertFalse(self.call(lambda k:k['parent_row'].update(process_name='battle.net-setup.exe')))
    def test_wrong_parent_hash_fails(self):self.assertFalse(self.call(lambda k:k['parent_row'].update(sha256='0'*64)))
    def test_reused_parent_pid_fails(self):self.assertFalse(self.call(lambda k:k.update(parent_identity_matches=False)))
    def test_other_folder_fails(self):self.assertFalse(self.call(lambda k:k.update(parent_path=k['parent_path'].parent.parent/'Agent.exe')))
    def test_reparse_fails(self):self.assertFalse(self.call(lambda k:k.update(is_reparse=lambda p:True)))
    def test_uninstrumented_parent_fails(self):self.assertFalse(self.call(lambda k:k['parent_row'].update(instrumented_before_resume=False)))
if __name__=='__main__':unittest.main()
