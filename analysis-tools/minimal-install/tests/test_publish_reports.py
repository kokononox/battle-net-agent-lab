import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'publish_reports.sh'
BRANCH = 'research/battlenet-minimal-install-isolation-2026-10-25'

@unittest.skipUnless(os.name == "posix", "Git publication runs only on Ubuntu")
class PublicationTests(unittest.TestCase):
    def git(self, cwd, *args):
        return subprocess.check_output(['git', '-C', str(cwd), *args], stderr=subprocess.DEVNULL, text=True).strip()

    def run_scenario(self, conflict=False):
        with tempfile.TemporaryDirectory() as root:
            root = pathlib.Path(root)
            remote, work, newer = (root / x for x in ['remote.git', 'work', 'newer'])
            self.git(root, 'init', '--bare', str(remote))
            self.git(root, 'clone', str(remote), str(work))
            for repo in [work]:
                self.git(repo, 'config', 'user.name', 'test')
                self.git(repo, 'config', 'user.email', 'test@example.invalid')
            self.git(work, 'checkout', '-b', BRANCH)
            (work/'base.txt').write_text('base')
            self.git(work, 'add', '.')
            self.git(work, 'commit', '-m', 'base')
            self.git(work, 'push', 'origin', BRANCH)
            self.git(root, 'clone', '--branch', BRANCH, str(remote), str(newer))
            self.git(newer, 'config', 'user.name', 'test')
            self.git(newer, 'config', 'user.email', 'test@example.invalid')
            report='reports/minimal-install-c1b/batch.json'
            (work/report).parent.mkdir(parents=True)
            (work/report).write_text('old-source report')
            self.git(work, 'add', '.')
            self.git(work, 'commit', '-m', 'report-only')
            if conflict:
                (newer/report).parent.mkdir(parents=True)
                (newer/report).write_text('newer report must survive')
            else:
                (newer/'unrelated.txt').write_text('newer code must survive')
            self.git(newer, 'add', '.')
            self.git(newer, 'commit', '-m', 'branch advanced')
            self.git(newer, 'push', 'origin', BRANCH)
            previous=self.git(newer, 'rev-parse', 'HEAD')
            result=subprocess.run(['bash',str(SCRIPT)],cwd=work,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if conflict:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.git(remote,'rev-parse',BRANCH), previous)
                self.assertEqual(self.git(remote,'show',f'{BRANCH}:{report}'),'newer report must survive')
            else:
                self.assertEqual(result.returncode,0)
                self.assertEqual(self.git(remote,'show',f'{BRANCH}:unrelated.txt'),'newer code must survive')
                self.assertEqual(self.git(remote,'show',f'{BRANCH}:{report}'),'old-source report')
                self.assertEqual(self.git(remote,'rev-parse',f'{BRANCH}^'),previous)
    def test_preserves_newer_code(self): self.run_scenario()
    def test_refuses_conflicting_reports(self): self.run_scenario(True)

if __name__ == '__main__': unittest.main()
