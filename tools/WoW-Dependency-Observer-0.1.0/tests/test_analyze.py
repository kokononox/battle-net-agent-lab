import json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import analyze as a
GAME=r'C:\Game\_retail_\Wow.exe'
def proc(i,pid,path,parent=999):
    return '<process><ProcessIndex>%s</ProcessIndex><ProcessId>%s</ProcessId><ParentProcessIndex>%s</ParentProcessIndex><ProcessName>%s</ProcessName><ImagePath>%s</ImagePath></process>'%(i,pid,parent,a.name(path),path)
def event(i,pid,op='TCP Send',path='10.0.0.2:50000 -> 1.1.1.1:443',detail='Length: 1,024, Other: private_value',result='SUCCESS',stack=True):
    f=('<stack><frame><depth>0</depth><address>0xffff000012345678</address><path>C:\\Windows\\System32\\ntdll.dll</path><location>PrivateFunction</location></frame><frame><path>C:\\Game\\_retail_\\wow_loader.dll</path></frame><frame><address>0x11111111</address></frame></stack>') if stack else ''
    return '<event><ProcessIndex>%s</ProcessIndex><PID>%s</PID><Operation>%s</Operation><Path>%s</Path><Detail>%s</Detail><Result>%s</Result>%s</event>'%(i,pid,op,path,detail,result,f)
def run(ps=None,events=None):
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'test.xml';p.write_text('<procmon><processlist>'+(''.join(ps) if ps is not None else proc(10,7284,GAME))+'</processlist><eventlist>'+(''.join(events) if events is not None else event(10,7284))+'</eventlist></procmon>')
        return a.analyze(p,GAME)
class Tests(unittest.TestCase):
    def test_root(self):self.assertEqual(run()['processes'][0]['relation'],'selected_executable')
    def test_case_path(self):self.assertTrue(run(ps=[proc(10,7284,GAME.lower())])['selected_process_found'])
    def test_wrong_root(self):self.assertFalse(run(ps=[proc(10,7284,r'C:\Other\Wow.exe')])['selected_process_found'])
    def test_root_no_events(self):self.assertEqual(run(events=[])['status'],'selected_process_without_observed_network')
    def test_child(self):self.assertEqual(run(ps=[proc(10,7284,GAME),proc(11,88,r'C:\Tools\Error.exe',10)],events=[event(11,88)])['processes'][1]['relation'],'descendant_by_process_index')
    def test_grandchild(self):self.assertEqual(len(run(ps=[proc(10,7284,GAME),proc(11,88,r'C:\Tools\Error.exe',10),proc(12,99,r'C:\Tools\Sender.exe',11)],events=[event(12,99)])['processes']),3)
    def test_pid_not_name(self):self.assertEqual(run(events=[event(777,7284)])['send_and_connect_groups'],[])
    def test_pid_mismatch(self):self.assertEqual(run(events=[event(10,22)])['processes'][0]['observed_events']['pid_mismatch_events'],1)
    def test_pid_reuse(self):self.assertEqual(run(ps=[proc(10,7284,GAME),proc(11,7284,r'C:\Other\app.exe')],events=[event(11,7284)])['send_and_connect_groups'],[])
    def test_sender_right(self):self.assertEqual(run()['send_and_connect_groups'][0]['destination']['ip'],'1.1.1.1')
    def test_send_size(self):self.assertEqual(run()['send_and_connect_groups'][0]['reported_successful_send_length_sum'],1024)
    def test_failed_send_no_bytes(self):self.assertEqual(run(events=[event(10,7284,result='ERROR')])['send_and_connect_groups'][0]['reported_successful_send_length_sum'],0)
    def test_connect_no_bytes(self):self.assertEqual(run(events=[event(10,7284,op='TCP Connect')])['send_and_connect_groups'][0]['reported_successful_send_length_sum'],0)
    def test_receive_no_wrong_destination(self):self.assertEqual(run(events=[event(10,7284,op='TCP Receive')])['send_and_connect_groups'],[])
    def test_udp(self):self.assertEqual(run(events=[event(10,7284,op='UDP Send')])['send_and_connect_groups'][0]['operation'],'UDP Send')
    def test_ipv6(self):self.assertEqual(a.endpoint('[2606:4700:4700::1111]:443')['port'],443)
    def test_ipv6_unbracketed(self):self.assertEqual(a.endpoint('2606:4700:4700::1111:443')['ip'],'2606:4700:4700::1111')
    def test_port_service(self):self.assertEqual(a.endpoint('1.1.1.1:https')['port'],443)
    def test_unknown_service(self):self.assertIsNone(a.endpoint('1.1.1.1:secret'))
    def test_invalid_port(self):self.assertIsNone(a.endpoint('1.1.1.1:99999'))
    def test_host_not_guessed(self):self.assertEqual(run(events=[event(10,7284,path='local:123 -> private.example:443')])['processes'][0]['unparsed_send_or_connect_destinations'],1)
    def test_stack_module(self):self.assertIn('wow_loader.dll',run()['send_and_connect_groups'][0]['game_folder_modules_in_stack'])
    def test_no_stack(self):self.assertEqual(run(events=[event(10,7284,stack=False)])['send_and_connect_groups'][0]['events_with_stack_frames'],0)
    def test_missing_frame_path(self):self.assertEqual(run()['send_and_connect_groups'][0]['frames_without_module_path'],1)
    def test_image(self):self.assertEqual(run(events=[event(10,7284,op='Load Image',path=r'C:\Game\_retail_\wow_loader.dll')])['processes'][0]['loaded_images_observed'][0]['name'],'wow_loader.dll')
    def test_same_folder_not_descendant(self):self.assertEqual(run(ps=[proc(10,7284,GAME),proc(15,80,r'C:\Game\_retail_\Helper.exe')],events=[event(15,80)])['processes'][1]['relation'],'same_game_folder_candidate_not_proven_related')
    def test_grouping(self):self.assertEqual(run(events=[event(10,7284),event(10,7284)])['send_and_connect_groups'][0]['events'],2)
    def test_private_data_not_exported(self):
        s=json.dumps(run());self.assertNotIn('C:\\',s);self.assertNotIn('PrivateFunction',s);self.assertNotIn('private_value',s);self.assertNotIn('0xffff',s)
    def test_entities_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.xml';p.write_text('<!DOCTYPE procmon [<!ENTITY a "x">]><procmon/>')
            with self.assertRaises(ValueError):a.analyze(p,GAME)
    def test_utf16_entity_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.xml';p.write_bytes('<!DOCTYPE procmon [<!ENTITY a "x">]><procmon/>'.encode('utf-16'))
            with self.assertRaises(ValueError):a.analyze(p,GAME)
    def test_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.xml';p.write_text('<procmon>')
            with self.assertRaises(Exception):a.analyze(p,GAME)
    def test_no_tree_schema(self):self.assertFalse(run(ps=[])['xml_process_table_recognized'])
    def test_unknown_module_sanitized(self):self.assertEqual(a.name('C:\\private\\name@secret.dll'),'other_module')
    def test_folder_prefix_not_match(self):self.assertFalse(a.under(r'C:\Game\_retail_evil\a.dll',r'C:\Game\_retail_'))
if __name__=='__main__':unittest.main()
