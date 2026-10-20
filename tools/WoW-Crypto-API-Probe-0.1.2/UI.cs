using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Collections.Generic;
using System.Drawing;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Web.Script.Serialization;
using System.Windows.Forms;
namespace WowCryptoProbe {
 sealed class Window:Form {
  Binding binding=null;string loaderHash=null;bool loginReached=false;
  string failureStage="not_started",failureKind=null;int? nativeError=null;
  string cdb=null,exe=null,dir=null,log=null,hash=null;Process proc=null;bool running=false,saved=false;string[] sslModules=new string[]{"libssl","libssl_3","libssl_3_x64","libssl_1_1","libssl_1_1_x64","ssleay32","ssleay64"}; int? exitCode=null,controlExit=null; bool controlPhase=false,controlPassed=false,gameStarted=false; Dictionary<string,bool> controlMarks=new Dictionary<string,bool>();
  Button bc=new Button(),bw=new Button(),bs=new Button();Label state=new Label();System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer();
  public Window(){Text="WoW Crypto API Probe 0.1.2";ClientSize=new Size(760,425);FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=false;
   var intro=new Label{Left=20,Top=15,Width=720,Height=115,Text="Lab-only native debugger test, not plaintext capture.\r\nCDB must come from Microsoft Debugging Tools for Windows (x64).\r\nThe game runs UNDER A DEBUGGER: compatibility/account risk is not ruled out.\r\nNo payload buffers or credentials are read. One known loader int3 is delivered to its handler.\r\nExported OpenSSL + Windows SSPI only; statically linked/private paths can be missed."};
   bc.Text="1. Choose cdb.exe (x64)";bc.SetBounds(20,140,225,35);bw.Text="2. Choose Wow.exe";bw.SetBounds(265,140,210,35);bs.Text="3. Start lab probe";bs.SetBounds(495,140,220,35);bs.Enabled=false;
   state.SetBounds(20,200,710,205);Controls.AddRange(new Control[]{intro,bc,bw,bs,state});
   string auto=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),@"Windows Kits\10\Debuggers\x64\cdb.exe");
   if(File.Exists(auto)){cdb=auto;state.Text="CDB found at the standard Windows Kits x64 location. Select Wow.exe.";}else state.Text="CDB not found. Install only Debugging Tools for Windows from the official Microsoft Windows SDK, or choose an existing x64 cdb.exe. No game will launch without it.";
   bc.Click+=delegate{PickCdb();};bw.Click+=delegate{PickWow();};bs.Click+=delegate{StartProbe();};timer.Interval=1500;timer.Tick+=delegate{Poll();};
   FormClosing+=delegate(object s,FormClosingEventArgs e){if(running)e.Cancel=MessageBox.Show(this,"CDB may still be debugging the game. Close the game normally first.\r\nIf stopped at a debugger prompt, type qd and Enter to detach and quit.\r\nClosing THIS window does not detach CDB. Close anyway?","Debugger still active",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes;};
  }
  void Ready(){bs.Enabled=cdb!=null&&exe!=null;}
  void PickCdb(){using(var d=new OpenFileDialog()){d.Filter="Microsoft CDB|cdb.exe";if(d.ShowDialog(this)!=DialogResult.OK)return;if(!String.Equals(Path.GetFileName(d.FileName),"cdb.exe",StringComparison.OrdinalIgnoreCase)){state.Text="Wrong debugger filename. Nothing launched.";return;}cdb=d.FileName;state.Text="Debugger selected. Use only Microsoft's official x64 CDB. The tool does not independently verify its signature.";Ready();}}
  void PickWow(){using(var d=new OpenFileDialog()){d.Filter="Previously analysed WoW|Wow.exe";if(d.ShowDialog(this)!=DialogResult.OK)return;try{if(!String.Equals(Path.GetFileName(d.FileName),"Wow.exe",StringComparison.OrdinalIgnoreCase)||Core.Sha(d.FileName)!=Core.Hash)throw new Exception();exe=d.FileName;state.Text="Analysed Wow.exe hash matched. Close all existing Wow processes before starting.";Ready();}catch{exe=null;Ready();state.Text="Wow.exe hash did not match the previously analysed file. Nothing launched.";}}}
  string PrivateDir(){string p=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"WowCryptoProbe",Guid.NewGuid().ToString("N"));var a=new DirectorySecurity();a.SetAccessRuleProtection(true,false);var u=WindowsIdentity.GetCurrent().User;a.SetOwner(u);foreach(var id in new SecurityIdentifier[]{u,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)})a.AddAccessRule(new FileSystemAccessRule(id,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));Directory.CreateDirectory(p,a);if(!new DirectoryInfo(p).GetAccessControl().AreAccessRulesProtected)throw new Exception();return p;}
  void FindSslModules(){
   var names=new HashSet<string>(sslModules,StringComparer.OrdinalIgnoreCase);
   var folders=new List<string>();folders.Add(Path.GetDirectoryName(exe));
   try{foreach(string sub in Directory.GetDirectories(folders[0])){if(folders.Count>=33)break;if((File.GetAttributes(sub)&FileAttributes.ReparsePoint)==0)folders.Add(sub);}}catch{}
   int seen=0;foreach(string folder in folders){try{foreach(string f in Directory.GetFiles(folder,"*ssl*.dll")){if(++seen>128)break;if((File.GetAttributes(f)&FileAttributes.ReparsePoint)!=0)continue;
     string name=Path.GetFileNameWithoutExtension(f).Replace('-','_').Replace('.','_');if(Core.ModuleOK(name))names.Add(name);}}catch{}if(seen>128)break;}
   sslModules=new List<string>(names).ToArray();Array.Sort(sslModules,StringComparer.OrdinalIgnoreCase);
  }
  void StartProbe(){if(exe==null||cdb==null||running)return;
   if(MessageBox.Show(this,"This starts the game under a native debugger and installs in-memory API breakpoints.\r\nIt may slow/fail to launch the game; no anti-cheat compatibility is guaranteed.\r\nDo not use a valuable account. No login is required for this initial test.\r\nA private local debugger log may include sensitive paths/debug strings; never upload it.\r\nContinue on the lab machine?","Explicit lab debugger consent",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
   bc.Enabled=bw.Enabled=bs.Enabled=false;
   try{Process[] ps=Process.GetProcessesByName("Wow");bool exists=ps.Length>0;foreach(var p in ps)p.Dispose();if(exists){state.Text="Close existing Wow processes normally first.";bc.Enabled=bw.Enabled=true;Ready();return;}
    failureStage="check_wow_identity";hash=Core.Sha(exe);if(hash!=Core.Hash)throw new Exception("source_changed");
    failureStage="check_loader_identity";loaderHash=Core.Sha(Path.Combine(Path.GetDirectoryName(exe),"wow_loader.dll"));if(loaderHash!=Core.LoaderHash)throw new InvalidOperationException("loader_identity_mismatch");
    failureStage="resolve_system_sspi_entry";binding=Binding.Resolve();
    failureStage="create_private_session";dir=PrivateDir();FindSslModules();
    failureStage="check_control_fixture";string control=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"ProbeControl.exe");
    if(!File.Exists(control))throw new Exception("control_fixture_missing");
    controlPhase=true;LaunchCdb(control);
    state.Text="CDB control must handle its own test int3 and exit successfully before the game launches.\r\nThen reach the login screen and close the game normally.\r\nIf a debugger prompt stops progress, type qd and Enter; do not force continuation of an unknown exception.\r\nIf the game is running but stuck, focus CDB, press Ctrl+C, then type qd and Enter.\r\nDo NOT close CDB with the X button: that can terminate the debuggee.\r\nOnly the final crypto-api-result JSON should be sent; never send the local debugger log.";
   }catch(Exception ex){Remember(ex);state.Text="Debugger launch/preflight failed. No security setting was changed. Send only the safe JSON, not local logs.";Save("preflight_or_debugger_launch_failed",new Dictionary<string,bool>(),false,false);}
  }
  void Remember(Exception ex){failureKind=ex.GetType().Name;var w=ex as System.ComponentModel.Win32Exception;if(w!=null)nativeError=w.NativeErrorCode;}

  void LaunchCdb(string target){
   failureStage=controlPhase?"control_write_script":"game_write_script";string prefix=controlPhase?"control-":"game-";
   string boot=Path.Combine(dir,prefix+"boot.txt");
   File.WriteAllText(boot,Core.Boot(controlPhase,sslModules,binding.Module,binding.Rva),Encoding.ASCII);
   log=Path.Combine(dir,prefix+"debugger-local.log");string symbols=Path.Combine(dir,"local-symbols");Directory.CreateDirectory(symbols);
   var si=new ProcessStartInfo(cdb);si.WorkingDirectory=Path.GetDirectoryName(target);si.UseShellExecute=false;si.CreateNoWindow=false;
   si.Arguments="-G -y "+Core.Quote(symbols)+" -logo "+Core.Quote(log)+" -cf "+Core.Quote(boot)+" "+Core.Quote(target);
   si.EnvironmentVariables.Remove("_NT_SYMBOL_PATH");si.EnvironmentVariables.Remove("_NT_ALT_SYMBOL_PATH");si.EnvironmentVariables.Remove("SSLKEYLOGFILE");
   failureStage=controlPhase?"control_start_cdb":"game_start_cdb";proc=Process.Start(si);if(proc==null)throw new Exception();if(!controlPhase)gameStarted=true;running=true;timer.Start();failureStage=controlPhase?"control_running":"game_running";
  }
  void Poll(){try{if(!proc.HasExited)return;running=false;timer.Stop();exitCode=proc.ExitCode;ReadAndSave();}catch{timer.Stop();state.Text="Could not confirm debugger exit. Close/detach it safely. No raw log should be uploaded.";}}
  void ReadAndSave(){bool capped=false;string text="";bool read=false;try{if(File.Exists(log)){using(var f=new FileStream(log,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)){byte[] b=new byte[Core.MaxRead+1];int n=0;while(n<b.Length){int k=f.Read(b,n,b.Length-n);if(k==0)break;n+=k;}capped=n>Core.MaxRead;int take=Math.Min(n,Core.MaxRead);if(capped){while(take>0&&b[take-1]!=10)take--;}text=Encoding.Default.GetString(b,0,take);read=true;}}}catch{}
   var marks=Core.Parse(text);bool hit=marks["WCP_SSPI_01"]||marks["WCP_SSLWRITE_01"]||marks["WCP_SSLWRITEEX_01"];
   if(controlPhase){
    controlExit=exitCode;exitCode=null;controlMarks=marks;controlPassed=read&&!capped&&controlExit==0&&marks["WCP_READY_01"]&&marks["WCP_CONTROL_01"]&&marks["WCP_CONTROL_INT3_DISPATCH_01"];
    if(!controlPassed){Save("debugger_control_failed_game_not_launched",marks,capped,read);return;}
    try{if(Core.Sha(exe)!=Core.Hash||Core.Sha(Path.Combine(Path.GetDirectoryName(exe),"wow_loader.dll"))!=Core.LoaderHash)throw new Exception();Process[] ps=Process.GetProcessesByName("Wow");bool exists=ps.Length>0;foreach(var p in ps)p.Dispose();if(exists)throw new Exception();
     proc.Dispose();proc=null;controlPhase=false;LaunchCdb(exe);state.Text="API + exception-delivery control passed; game test launched.\r\nReach the login screen, then close the game normally. No account login required.\r\nIf stopped at an unknown debugger exception/prompt: type qd and Enter.\r\nIf running but stuck: focus CDB, Ctrl+C, then qd and Enter.\r\nDo not use the debugger window X button or send raw logs.";
    }catch(Exception ex){Remember(ex);Save("control_passed_but_game_launch_failed",new Dictionary<string,bool>(),false,false);}return;
   }
   loginReached=MessageBox.Show(this,"Did the actual game window reach its normal login screen during THIS run?\r\nChoose No if it stayed at a debugger prompt or never opened.","Game run confirmation",MessageBoxButtons.YesNo,MessageBoxIcon.Question)==DialogResult.Yes;
   bool syntax=text.IndexOf("Syntax error",StringComparison.OrdinalIgnoreCase)>=0||text.IndexOf("Couldn't resolve error",StringComparison.OrdinalIgnoreCase)>=0;
   string result=!read?"debugger_log_unavailable":capped?"bounded_log_incomplete":hit?(syntax?"api_entry_observed_with_setup_warnings":"api_entry_observed"):syntax?"probe_setup_errors_observed":!loginReached?"game_did_not_reach_login":marks["WCP_READY_01"]?"no_target_api_entry_observed":"debugger_probe_not_confirmed";
   Save(result,marks,capped,read);
  }
  void Save(string status,Dictionary<string,bool> marks,bool capped,bool read){if(saved)return;try{var d=new Dictionary<string,object>();d["schema"]="wow-crypto-api-probe-1";d["last_stage"]=failureStage;d["failure_exception_kind"]=failureKind;d["native_error_code"]=nativeError;d["version"]="0.1.2";d["loader_sha256"]=loaderHash;d["loader_hash_matched"]=loaderHash==Core.LoaderHash;
    d["sspi_binding_module"]=binding==null?null:binding.Module;d["sspi_binding_rva"]=binding==null?(object)null:binding.Rva;d["sspi_binding_file_sha256"]=binding==null?null:binding.FileHash;
    d["binding_resolved_in_wrapper_not_attested_target_memory"]=true;d["known_loader_int3_one_shot_dispatch_requested"]=gameStarted;d["known_loader_int3_dispatch_marker_observed"]=marks.ContainsKey("WCP_LOADER_INT3_DISPATCH_01")&&marks["WCP_LOADER_INT3_DISPATCH_01"];d["game_loader_exception_handler_execution_independently_proven"]=false;d["global_exception_filters_relaxed"]=false;d["game_reached_login_user_confirmed"]=loginReached;d["dll_load_script_callback_used"]=false;d["ssl_deferred_module_candidates"]=sslModules;d["ssl_candidate_names_are_not_runtime_use_proof"]=true;d["status"]=status;d["selected_wow_sha256"]=hash;d["expected_binary_hash_matched"]=hash==Core.Hash;d["active_tls_backend_fully_identified"]=false;d["debugger_exit_code"]=exitCode;d["exact_marker_lines_observed"]=marks;d["local_log_read"]=read;d["log_prefix_limit_hit"]=capped;d["maximum_log_bytes_inspected"]=Core.MaxRead;d["debugger_log_raw_size_capped"]=false;d["debugger_control_passed"]=controlPassed;d["control_markers"]=controlMarks;d["control_debugger_exit_code"]=controlExit;d["game_started_under_native_debugger"]=gameStarted;d["api_breakpoints_requested"]=gameStarted;d["in_memory_breakpoints_may_change_execution"]=true;d["all_breakpoints_resolved_verified"]=false;d["statically_linked_or_hidden_crypto_covered"]=false;d["child_processes_covered"]=false;d["destinations_attributed"]=false;d["sspi_hit_is_not_schannel_or_remote_upload_proof"]=true;d["payload_buffers_read_by_probe_commands"]=false;d["cpu_or_bios_upload_proven"]=false;d["plaintext_captured_by_probe"]=false;d["raw_debugger_output_included"]=false;d["raw_logs_uploaded"]=false;d["certificate_firewall_hosts_execution_policy_changed"]=false;d["kill_or_suspend_command_sent_by_wrapper"]=false;d["debugger_selected_signature_independently_verified"]=false;
    d["limits"]=new string[]{"API-entry metadata only; not destination attribution, send success, or content evidence.","Zero hits are inconclusive: only initial exported-symbol scan and named deferred SSL modules; later other-named DLLs, static/private crypto and other processes can be missed.","SSPI EncryptMessage can serve non-TLS security packages; its hit alone does not prove Schannel.","Debugger timing and breakpoints alter execution and may prevent normal game behaviour.",
    "One previously observed, disk-hash-bound loader int3 address requests one-shot gN delivery, not force-handled continuation. Current loaded target bytes and handler execution are not independently attested. Other unknown exceptions keep default stops.",
    "Control must finish with exit zero after its own VEH handles an int3 forwarded by the same one-shot gN mechanism. This still does not guarantee game compatibility.",
    "SSPI entry resolves through Windows GetProcAddress in the wrapper; module plus RVA avoids forwarder-name lookup, but loaded target bytes are not independently attested.","Debugger output is local and may contain paths/debug strings; only fixed standalone markers enter this report.","Bounded log prefix only, no hard disk-size cap. A truncated report may miss later hits.","Probe-ready/scan markers prove script progress only, not resolution of every requested breakpoint.","Local logs are not removed automatically. Closing the wrapper does not detach CDB."};
    string p=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"crypto-api-result-"+Guid.NewGuid().ToString("N")+".json");using(var f=new FileStream(p,FileMode.CreateNew,FileAccess.Write,FileShare.None)){byte[] b=new UTF8Encoding(false).GetBytes(new JavaScriptSerializer().Serialize(d));f.Write(b,0,b.Length);}saved=true;
    state.Text="Status: "+status+"\r\nSend ONLY: "+Path.GetFileName(p)+"\r\nDo not upload debugger-local.log or the private session folder.\r\nNo hit does not mean no encryption or no telemetry.";
   }catch{state.Text="Could not save the safe JSON next to the tool. Do not upload local debugger logs.";}}
  protected override void Dispose(bool disposing){if(disposing){timer.Dispose();if(proc!=null)proc.Dispose();}base.Dispose(disposing);}
 }
 static class Entry{[STAThread]static void Main(){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new Window());}}
}
