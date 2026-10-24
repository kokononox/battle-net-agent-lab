import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import verify_host_id as audit


class VersionGate(unittest.TestCase):
    def test_empty_rejected(self):
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            audit.analyze(b'')

    def test_other_image_rejected(self):
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            audit.analyze(b'MZ'+b'\0'*4094)

    def test_malformed_pe_rejected_after_mocked_hash(self):
        with patch.object(audit.hashlib,'sha256') as h:
            h.return_value.hexdigest.return_value=audit.SHA256
            with self.assertRaisesRegex(ValueError,'Invalid PE'):
                audit.analyze(b'\0'*512)


@unittest.skipUnless(os.environ.get('AGENT_AUDIT_IMAGE'), 'Private pinned image not supplied')
class PinnedImage(unittest.TestCase):
    def setUp(self):
        self.image=Path(os.environ['AGENT_AUDIT_IMAGE']).read_bytes()

    def test_anchors_and_privacy(self):
        r=audit.analyze(self.image)
        self.assertEqual(r['wire_path'],'/1/4/1')
        self.assertEqual(len(r['checks']),25)
        self.assertEqual(r['runtime_branch_selected'],'not_established')
        self.assertNotIn('body_sample_base64',json.dumps(r))

    def test_mutation_rejected_by_version_gate(self):
        b=bytearray(self.image); b[-1]^=1
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            audit.analyze(bytes(b))

    def test_instruction_mutation_and_input_unchanged(self):
        before=hashlib.sha256(self.image).digest()
        audit.analyze(self.image)
        self.assertEqual(before,hashlib.sha256(self.image).digest())
        b=bytearray(self.image)
        b[0x7d45d2-0x400c00]^=1
        with patch.object(audit.hashlib,'sha256') as h:
            h.return_value.hexdigest.return_value=audit.SHA256
            with self.assertRaisesRegex(ValueError,'anchor mismatch'):
                audit.analyze(bytes(b))


if __name__=='__main__': unittest.main()
