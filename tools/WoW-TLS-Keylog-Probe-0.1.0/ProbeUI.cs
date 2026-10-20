using System;
using System.IO;
using System.Drawing;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace WowTlsProbe {
    sealed class ProbeWindow : Form {
        Label status=new Label(); Button choose=new Button(); Button start=new Button();
        System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer();
        string selected=null, privateDir=null, keyPath=null, launchedHash=null;
        Process game=null; bool running=false, finalised=false, permissionProtected=false;
        DateTime started; int? launchedPid=null; bool keyFileSeen=false; long largestSize=0;
        public ProbeWindow() {
            Text="WoW TLS Keylog Capability Probe 0.1.0"; Width=760; Height=440;
            StartPosition=FormStartPosition.CenterScreen; FormBorderStyle=FormBorderStyle.FixedDialog; MaximizeBox=false;
            Label intro=new Label {Left=20,Top=20,Width=700,Height=112,Text=
              "Capability test only. No proxy, CA, firewall change, injection or debugger.\r\n"+
              "Choose the previously analysed Wow.exe (12.1.5.70448), then Start.\r\n"+
              "Reach the login screen; no account sign-in is required by this test.\r\n"+
              "Close the game normally to finish. Do NOT upload any keylog or the private folder."};
            choose.Text="1. Choose Wow.exe"; choose.SetBounds(20,140,210,36);
            start.Text="2. Start capability test"; start.SetBounds(250,140,230,36);start.Enabled=false;
            status.SetBounds(20,195,700,175);status.Text="No game selected. Close any existing WoW process first.";
            Controls.AddRange(new Control[]{intro,choose,start,status});
            choose.Click+=delegate{ChooseFile();}; start.Click+=delegate{Launch();};
            timer.Interval=1000;timer.Tick+=delegate{Poll();};
            FormClosing+=delegate(object sender,FormClosingEventArgs e){
                if(running) {
                    try {
                        if(game!=null && game.HasExited) {
                            running=false;timer.Stop();
                            KeylogSummary r=Core.ReadSummary(keyPath);
                            SaveResult(r.ValidLines>0?"keylog_candidate_available":"no_usable_keylog_in_this_run",r);
                        }
                    }catch{}
                }
                if(running) {
                    DialogResult answer=MessageBox.Show(this,
                      "The game is still running, or its exit cannot be confirmed.\r\n"+
                      "Close the game normally first. This tool never kills it.\r\n"+
                      "Closing this window does NOT stop possible key export by the game/children.\r\n"+
                      "Close this window anyway?", "Game lifetime not finished",MessageBoxButtons.YesNo,MessageBoxIcon.Warning);
                    e.Cancel=(answer!=DialogResult.Yes);
                }
            };
        }
        void ChooseFile() {
            using(OpenFileDialog d=new OpenFileDialog()) {
                d.Filter="World of Warcraft executable|Wow.exe";d.Title="Select the previously analysed Retail Wow.exe";
                if(d.ShowDialog(this)!=DialogResult.OK)return;
                try {
                    string p=Path.GetFullPath(d.FileName);
                    if(!String.Equals(Path.GetFileName(p),"Wow.exe",StringComparison.OrdinalIgnoreCase))throw new Exception("wrong_executable_name");
                    FileInfo fi=new FileInfo(p);if(fi.Length<1024 || fi.Length>150L*1024*1024)throw new Exception("source_size_out_of_scope");
                    status.Text="Checking the selected file identity...";Refresh();
                    string hash=Core.HashFile(p);
                    if(hash!=Core.ExpectedWowSha256)throw new Exception("source_hash_not_the_previously_analysed_build");
                    selected=p;start.Enabled=true;
                    status.Text="Previously analysed binary matched.\r\nStart sets SSLKEYLOGFILE only in the launched process environment.\r\n"+
                      "It does not change the Windows/user environment.\r\nAny raw keys stay under your private LocalAppData folder.";
                }catch {selected=null;start.Enabled=false;status.Text="Selection refused: file identity could not be matched to the analysed build. Nothing launched.";}
            }
        }
        bool ExistingWow() {
            // Refuse all same-name instances to avoid single-instance handoff into an old environment.
            Process[] ps=Process.GetProcessesByName("Wow");bool found=ps.Length>0;
            foreach(Process p in ps)p.Dispose();return found;
        }
        void MakePrivateDirectory() {
            string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"WowTlsProbe");
            Directory.CreateDirectory(root);
            privateDir=Path.Combine(root,Guid.NewGuid().ToString("N"));
            DirectorySecurity acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
            SecurityIdentifier user=WindowsIdentity.GetCurrent().User;
            acl.SetOwner(user);
            acl.AddAccessRule(new FileSystemAccessRule(user,FileSystemRights.FullControl,
              InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),FileSystemRights.FullControl,
              InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            Directory.CreateDirectory(privateDir,acl); // Fail before launching if a protected output folder cannot be created.
            DirectoryInfo di=new DirectoryInfo(privateDir);
            permissionProtected=di.GetAccessControl().AreAccessRulesProtected;
            if(!permissionProtected)throw new Exception("private_folder_acl_not_protected");
            keyPath=Path.Combine(privateDir,"session-secrets.keylog");
            if(File.Exists(keyPath))throw new Exception("keylog_path_not_fresh");
        }
        void Launch() {
            if(selected==null || running)return;
            choose.Enabled=false;start.Enabled=false;
            try {
                if(ExistingWow()) {status.Text="Existing Wow process found. Close it normally and retry. Nothing launched.";choose.Enabled=true;start.Enabled=true;return;}
                launchedHash=Core.HashFile(selected);if(launchedHash!=Core.ExpectedWowSha256)throw new Exception("source_changed");
                MakePrivateDirectory();
                ProcessStartInfo psi=new ProcessStartInfo(selected);
                psi.WorkingDirectory=Path.GetDirectoryName(selected);psi.UseShellExecute=false;
                psi.EnvironmentVariables["SSLKEYLOGFILE"]=keyPath;
                started=DateTime.UtcNow;
                game=Process.Start(psi);if(game==null)throw new Exception("launch_failed");
                launchedPid=game.Id;running=true;timer.Start();
                status.Text="Game launched. Reach the login screen, then close the game normally.\r\n"+
                  "No need to log into an account for this initial capability test.\r\n"+
                  "The result is generated only after this launched process exits.";
            }catch {
                status.Text="Preflight/launch did not complete. No policy, firewall or certificate changed.";
                SaveResult("launch_or_preflight_failed",new KeylogSummary{State="not_checked"});
            }
        }
        void Poll() {
            try {
                if(File.Exists(keyPath)) {keyFileSeen=true;try{largestSize=Math.Max(largestSize,new FileInfo(keyPath).Length);}catch{}}
                if(game.HasExited) {
                    running=false;timer.Stop();
                    KeylogSummary r=Core.ReadSummary(keyPath);
                    SaveResult(r.ValidLines>0?"keylog_candidate_available":"no_usable_keylog_in_this_run",r);
                    return;
                }
                if((DateTime.UtcNow-started).TotalSeconds>90 || largestSize>Core.MaxReadBytes)
                    status.Text="Please close the game normally now to finish.\r\n"+
                      "This tool does not kill/pause it. Key export may continue until the game and any inheriting children exit.\r\n"+
                      "Only a bounded prefix is inspected; the raw output file has no enforced disk-size cap.";
            }catch {
                timer.Stop();status.Text="Process monitoring failed. Close the game normally before closing this tool.\r\n"+
                  "Possible key export can outlive the monitor. Do not upload raw keys.";
                // Keep blocking ordinary window-close while child lifetime remains uncertain.
                SaveResult("process_monitoring_failed",new KeylogSummary{State="not_checked"});
            }
        }
        void SaveResult(string state,KeylogSummary keys) {
            if(finalised)return;
            try {
                Dictionary<string,object> report=new Dictionary<string,object>();
                report["schema"]="wow-tls-keylog-capability-1";report["tool_version"]="0.1.0";report["status"]=state;
                report["selected_exe_name"]="Wow.exe";report["selected_sha256"]=launchedHash;
                report["launched_pid"]=launchedPid;report["expected_binary_hash_matched"]=launchedHash==Core.ExpectedWowSha256;
                report["child_environment_only"]=true;report["global_environment_changed"]=false;
                report["private_directory_acl_protected"]=permissionProtected;
                report["keylog_file_observed"]=keyFileSeen || keys.BytesObserved>0;
                report["keylog_state"]=keys.State;report["keylog_bytes_inspected"]=keys.BytesObserved;
                report["valid_keylog_format_lines"]=keys.ValidLines;report["invalid_noncomment_lines"]=keys.InvalidLines;
                report["keylog_labels"]=keys.Labels;report["read_limit_hit"]=keys.ReadLimitHit;
                report["maximum_bytes_inspected"]=Core.MaxReadBytes;report["raw_file_size_cap_enforced"]=false;
                report["key_export_writer_pid_attributed"]=false;report["child_process_lifetime_coverage_complete"]=false;
                report["keys_matched_to_packet_capture"]=false;report["active_tls_backend_proven"]=false;
                report["plaintext_captured"]=false;report["cpu_or_bios_upload_proven"]=false;
                report["process_injected_or_debugger_attached"]=false;report["pcap_recorded"]=false;
                report["certificate_or_firewall_or_execution_policy_changed"]=false;
                report["raw_secrets_included_in_report"]=false;report["raw_secrets_uploaded"]=false;
                report["game_killed_or_suspended_by_tool"]=false;
                report["limits"]=new string[]{
                  "Capability test, not a content or no-telemetry verdict.",
                  "No keylog does not prove no TLS: backend/export support, timing or launch handoff may differ.",
                  "Recognised text format is not proof that secrets decrypt a captured session.",
                  "A launched process or inheriting child may write keys; exact writer PID is not attributed.",
                  "If supported, key export may continue for the process/child lifetime. No hard recording/disk cap.",
                  "Raw keys remain local in a protected LocalAppData folder; do not share that folder.",
                  "Ordinary game execution may itself use the network and write its normal local files.",
                  "No modules-only backend inference; no packet payload/content captured by this probe.",
                  "Expected SHA is the file hash checked before launch, not a race-free loaded-memory attestation."};
                string json=new JavaScriptSerializer().Serialize(report);
                string path=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"tls-capability-result-"+Guid.NewGuid().ToString("N")+".json");
                using(FileStream f=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
                    byte[] b=new System.Text.UTF8Encoding(false).GetBytes(json);f.Write(b,0,b.Length);
                }
                finalised=true;
                string note=keys.ValidLines>0 ? "Keylog-format lines were found. This is NOT yet successful traffic decryption." : "No usable keys observed in this run. This is NOT a no-TLS/no-telemetry verdict.";
                status.Text=note+"\r\nShare ONLY: "+Path.GetFileName(path)+"\r\nNo account identifiers, paths or raw secret values are included in that JSON.\r\nDo not share session-secrets.keylog or the private LocalAppData folder.";
                if(!running)MessageBox.Show(this,status.Text,"Capability result");
            }catch {status.Text="Could not save the safe JSON next to this program. Do not upload any raw keylog. Close the game normally.";}
        }
        protected override void Dispose(bool disposing) {
            if(disposing){timer.Dispose();if(game!=null)game.Dispose();}
            base.Dispose(disposing);
        }
    }
    static class Entry {
        [STAThread] static int Main(string[] args) {
            if(args.Length==1 && args[0]=="--self-test") {
                try{int n=Core.SelfTest();MessageBox.Show("Core self-tests passed: "+n);return 0;}
                catch{MessageBox.Show("Core self-test failed.");return 1;}
            }
            Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new ProbeWindow());return 0;
        }
    }
}
