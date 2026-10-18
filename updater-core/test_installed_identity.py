import hashlib,json,unittest
import installed_identity as v

CONFIG=b'build-uid = wow\nbuild-name = WOW-69933patch12.1.0_Retail\n'
KEY=hashlib.md5(CONFIG).hexdigest()
def info(tags='Windows x86_64 EU enUS speech text',active='1',version='12.1.0.69933',key=KEY):
    return ('Active!DEC:1|Build Key!HEX:16|Version!STRING:0|Tags!STRING:0|Product!STRING:0\n'+f'{active}|{key}|{version}|{tags}|wow\n').encode()

class BaselineTests(unittest.TestCase):
    def test_consistent_metadata(self):
        r=v.validate(info(),CONFIG);self.assertEqual(r['installed_version_from_uploaded_metadata'],'12.1.0.69933')
    def test_profile(self):
        r=v.validate(info(),CONFIG);self.assertEqual(r['profile_from_uploaded_metadata'],{'platform':'Windows','architecture':'x86_64','region':'EU','locales':['enUS']})
    def test_inactive_not_selected(self):
        with self.assertRaises(v.InvalidMetadata):v.validate(info(active='0'),CONFIG)
    def test_duplicate_active_refused(self):
        raw=info();raw+=raw.splitlines()[-1]+b'\n'
        with self.assertRaises(v.InvalidMetadata):v.validate(raw,CONFIG)
    def test_md5_conflict(self):
        with self.assertRaises(v.InvalidMetadata):v.validate(info(),CONFIG+b' ')
    def test_version_conflict(self):
        with self.assertRaises(v.InvalidMetadata):v.validate(info(version='12.1.5.70391'),CONFIG)
    def test_unknown_tags_no_guess(self):
        with self.assertRaises(v.InvalidMetadata):v.validate(info(tags='Windows x86_64 EU enUS UNRECOGNIZED'),CONFIG)
    def test_private_qualifiers_not_exported(self):
        r=v.validate(info(tags='Windows x86_64 EU enUS acct-TESTSECRET? geoip-TESTSECRET?'),CONFIG)
        self.assertEqual(r['private_optional_qualifiers_withheld'],2)
        self.assertNotIn('TESTSECRET',json.dumps(r))
    def test_ambiguous_platform(self):
        with self.assertRaises(v.InvalidMetadata):v.validate(info(tags='Windows OSX x86_64 EU enUS'),CONFIG)
    def test_empty_tags(self):
        with self.assertRaises(v.InvalidMetadata):v.validate(info(tags=''),CONFIG)
    def test_size_limit(self):
        with self.assertRaises(v.InvalidMetadata):v.validate(b'x'*1048577,CONFIG)
    def test_duplicate_config_identity(self):
        c=CONFIG+b'build-uid = wow\n'
        with self.assertRaises(v.InvalidMetadata):v.validate(info(key=hashlib.md5(c).hexdigest()),c)
    def test_never_infers_live_or_install_proof(self):
        r=v.validate(info(),CONFIG)
        self.assertFalse(r['live_installation_state_revalidated']);self.assertFalse(r['apply_authorized'])
        self.assertIsNone(r['required_network_download_bytes'])

if __name__=='__main__':unittest.main()
