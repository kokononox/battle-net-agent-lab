using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Drawing;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using CdbControl;
sealed class Runner:Form {
 string cdb=null,root=null,proofPath=null,log=null,phase="not_started";Process active=null;bool running=false,baselinePassed=false,debuggerMode=false;int? baselineExit=null,debuggerExit=null;int[] baselineProof=null;
 Button choose=new Button(),start=new Button(),snapshot=new Button();Label label=new Label();System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer();
 public Runner(){Text="CDB Control Only 0.1.3 — NO GAME LAUNCH";ClientSize=new Size(750,375);FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=false;
  var intro=new Label{Left=15,Top=15,Width=710,Height=100,Text="CONTROL ONLY: this package cannot select, launch or patch WoW.\r\nIt tests its own small fixture first normally, then under CDB.\r\nOnly the fixture's own exception-context RIP may advance by one byte at its exact int3.\r\nNo payloads, credentials, game configuration, firewall or certificates are touched."};
  choose.Text="Choose official x64 cdb.exe";choose.SetBounds(15,125,240,34);start.Text="Start control tests";start.SetBounds(275,125,190,34);snapshot.Text="Save diagnostic now";snapshot.SetBounds(485,125,230,34);snapshot.Enabled=false;
  label.SetBounds(15,180,710,180);Controls.AddRange(new Control[]{intro,choose,start,snapshot,label});
  string p=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),@"Windows Kits\10\Debuggers\x64\cdb.exe");if(File.Exists(p)){cdb=p;label.Text="Installed CDB found. Start control tests.";}else label.Text="Select the already installed official Microsoft x64 cdb.exe. No installation is performed.";
  choose.Click+=delegate{using(var d=new OpenFileDialog()){d.Filter="Microsoft CDB|cdb.exe";if(d.ShowDialog(this)==DialogResult.OK&&String.Equals(Path.GetFileName(d.FileName),"cdb.exe",StringComparison.OrdinalIgnoreCase)){cdb=d.FileName;label.Text="CDB selected. Its signature is not independently verified by this helper.";}}};
  start.Click+=delegate{Start();};snapshot.Click+=delegate{Save("manual_snapshot",null);};timer.Interval=1000;timer.Tick+=delegate{Poll();};
  FormClosing+=delegate(object s,FormClosingEventArgs e){if(running)e.Cancel=MessageBox.Show(this,"A control process/debugger is still running. This window does not stop it.\r\nIn a stopped CDB prompt, type qd and Enter. Close this window anyway?","Control running",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes;};
 }
 string Session(){string p=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"CdbControlOnly",Guid.NewGuid().ToString("N"));var a=new DirectorySecurity();a.SetAccessRuleProtection(true,false);var user=WindowsIdentity.GetCurrent().User;a.SetOwner(user);foreach(var id in new SecurityIdentifier[]{user,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)})a.AddAccessRule(new FileSystemAccessRule(id,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));Directory.CreateDirectory(p,a);if(!new DirectoryInfo(p).GetAccessControl().AreAccessRulesProtected)throw new InvalidOperationException();return p;}
 void Start(){if(running||cdb==null){label.Text="Choose an existing official x64 cdb.exe first.";return;}start.Enabled=choose.Enabled=false;
  try{Shared.Tests();root=Session();phase="baseline_start";Launch(false);label.Text="Running the fixture WITHOUT a debugger first. No game is involved.";}
  catch{Save("preflight_failed",null);}
 }
 void Launch(bool debug){debuggerMode=debug;string prefix=debug?"debug-":"baseline-";proofPath=Path.Combine(root,prefix+"proof.bin");using(var f=new FileStream(proofPath,FileMode.CreateNew,FileAccess.Write,FileShare.ReadWrite)){f.SetLength(Shared.Size);}
  string exe=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"ControlFixture.exe");if(!File.Exists(exe))throw new FileNotFoundException();
  var si=new ProcessStartInfo();si.WorkingDirectory=AppDomain.CurrentDomain.BaseDirectory;si.UseShellExecute=false;
  if(debug){string boot=Path.Combine(root,"control-boot.txt");File.WriteAllText(boot,Shared.Commands(),System.Text.Encoding.ASCII);log=Path.Combine(root,"debugger-local.log");string symbols=Path.Combine(root,"local-symbols");Directory.CreateDirectory(symbols);
   si.FileName=cdb;si.Arguments="-G -y "+Shared.Quote(symbols)+" -logo "+Shared.Quote(log)+" -cf "+Shared.Quote(boot)+" "+Shared.Quote(exe)+" "+Shared.Quote(proofPath);si.CreateNoWindow=false;
  }else{si.FileName=exe;si.Arguments=Shared.Quote(proofPath);si.CreateNoWindow=true;}
  si.EnvironmentVariables.Remove("SSLKEYLOGFILE");si.EnvironmentVariables.Remove("_NT_SYMBOL_PATH");si.EnvironmentVariables.Remove("_NT_ALT_SYMBOL_PATH");
  active=Process.Start(si);if(active==null)throw new InvalidOperationException();running=true;snapshot.Enabled=true;phase=debug?"debugger_running":"baseline_running";timer.Start();
 }
 int[] ReadProof(string p){try{if(new FileInfo(p).Length!=Shared.Size)return null;using(var m=MemoryMappedFile.CreateFromFile(p,FileMode.Open,null,Shared.Size))using(var v=m.CreateViewAccessor(0,Shared.Size,MemoryMappedFileAccess.Read)){var a=new int[16];for(int i=0;i<16;i++)a[i]=v.ReadInt32(i*4);return a;}}catch{return null;}}
 string ReadLog(out bool capped){capped=false;try{if(log==null||!File.Exists(log))return "";using(var f=new FileStream(log,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)){byte[] b=new byte[1048577];int n=0;while(n<b.Length){int k=f.Read(b,n,b.Length-n);if(k==0)break;n+=k;}capped=n>1048576;int take=Math.Min(n,1048576);if(capped)while(take>0&&b[take-1]!=10)take--;return System.Text.Encoding.Default.GetString(b,0,take);}}catch{return "";}}
 void Poll(){try{if(!active.HasExited)return;running=false;timer.Stop();int exit=active.ExitCode;
   if(!debuggerMode){phase="baseline_exited";baselineExit=exit;baselineProof=ReadProof(proofPath);baselinePassed=exit==0&&Shared.ProofOK(baselineProof)&&baselineProof[11]==0;if(!baselinePassed){Save("baseline_fixture_failed_cdb_not_started",null);return;}active.Dispose();active=null;phase="debugger_start";Launch(true);label.Text="Baseline passed. Running the SAME fixture under CDB.\r\nIf CDB stops at an unexpected prompt, type qd and Enter. Do not force an unknown exception.\r\nSave diagnostic now can capture progress without closing CDB.\r\nOnly send the control-only-result JSON; never the local debugger log.";
   }else{phase="debugger_exited";debuggerExit=exit;bool cap;var marks=Shared.Markers(ReadLog(out cap));int[] now=ReadProof(proofPath);bool ok=exit==0&&!cap&&Shared.ProofOK(now)&&now[11]==1&&marks["WCC_READY_01"]&&marks["WCC_API_01"]&&marks["WCC_DISPATCH_01"];Save(ok?"control_fixture_verified":"debugger_fixture_incomplete",null);}
  }catch{timer.Stop();Save("monitor_or_launch_failed",null);}
 }
 object SafeProof(int[] p){if(p==null||p.Length!=16||p[0]!=Shared.Magic||p[1]!=Shared.Version)return null;return new {phase=p[2],matched_exception_count=p[3],exception_code=p[4],exception_code_hex=unchecked((uint)p[4]).ToString("X8"),expected_address_matched=p[5]==1,rip_category=p[6],rip_category_label=p[6]==1?"at_int3":p[6]==2?"after_int3":p[6]==3?"unexpected":"not_recorded",fixture_context_rip_advanced_one_byte=p[7]==1,returned_after_debugbreak=p[8]==1,fixture_result=p[9],fixture_error=p[10],debugger_present_after_return=p[11]==1};}
 void Save(string status,object unused){try{bool cap;string text=ReadLog(out cap);var d=new Dictionary<string,object>();d["schema"]="cdb-control-only-1";d["version"]="0.1.3";d["status"]=status;d["last_stage"]=phase;d["debugger_or_fixture_still_running"]=running;d["baseline_passed"]=baselinePassed;d["baseline_exit_code"]=baselineExit;d["baseline_proof"]=SafeProof(baselineProof);d["debugger_exit_code"]=debuggerExit;d["current_fixture_proof"]=SafeProof(ReadProof(proofPath));d["exact_debugger_markers"]=Shared.Markers(text);d["log_prefix_capped"]=cap;d["syntax_error_observed"]=text.IndexOf("Syntax error",StringComparison.OrdinalIgnoreCase)>=0;d["game_launched"]=false;d["game_memory_or_game_context_modified"]=false;d["fixture_own_context_may_be_modified"]=true;d["payloads_or_tls_keys_captured"]=false;d["raw_local_logs_included_or_uploaded"]=false;d["certificate_firewall_hosts_execution_policy_changed"]=false;d["all_runtime_branches_native_tested_by_developer"]=false;d["limits"]=new string[]{"Control-only; success is not game/anti-cheat compatibility or TLS evidence.","Only fixture's own single matching breakpoint context can advance one byte; no game pointer or game EXE is selected.","Current proof is a bounded 64-byte shared record; manual snapshots while running may be mid-update.","CDB exit alone is not proof of fixture completion; both fixed debugger markers and fixture final state are required.","Local raw debugger logs may contain private paths/debug strings; do not upload them.","Log read bounded at 1 MiB, raw log disk size/time is not capped. Close/detach the debugger normally."};
   string outp=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"control-only-result-"+Guid.NewGuid().ToString("N")+".json");using(var f=new FileStream(outp,FileMode.CreateNew,FileAccess.Write,FileShare.None)){byte[] b=new System.Text.UTF8Encoding(false).GetBytes(new JavaScriptSerializer().Serialize(d));f.Write(b,0,b.Length);}label.Text="Status: "+status+"\r\nSend ONLY: "+Path.GetFileName(outp)+"\r\nNo game has been launched. Do not send local logs.\r\nIf CDB is still running, qd at its prompt detaches it; this tool does not kill it.";
  }catch{label.Text="Could not save the safe JSON next to this helper. Do not upload raw logs.";}}
 protected override void Dispose(bool disposing){if(disposing){timer.Dispose();if(active!=null)active.Dispose();}base.Dispose(disposing);}
 [STAThread]static void Main(){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new Runner());}
}
