using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace WowTlsProbe {
    public sealed class KeylogSummary {
        public string State = "not_checked";
        public long BytesObserved;
        public int ValidLines;
        public int InvalidLines;
        public bool ReadLimitHit;
        public Dictionary<string,int> Labels = new Dictionary<string,int>(StringComparer.Ordinal);
    }
    public static class Core {
        public const string ExpectedWowSha256 = "1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a";
        public const int MaxReadBytes = 1048576;
        static readonly HashSet<string> Labels = new HashSet<string>(StringComparer.Ordinal) {
            "CLIENT_RANDOM", "CLIENT_EARLY_TRAFFIC_SECRET", "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET", "EARLY_EXPORTER_SECRET"
        };
        public static bool IsHex(string s, int length) {
            if (s == null || s.Length != length) return false;
            foreach(char c in s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
            return true;
        }
        public static string GetLabel(string line) {
            if (line == null || line.Length > 512) return null;
            string[] p = line.Trim().Split(new char[]{' ', '\t'}, StringSplitOptions.RemoveEmptyEntries);
            if (p.Length != 3 || !Labels.Contains(p[0]) || !IsHex(p[1],64)) return null;
            if (p[0] == "CLIENT_RANDOM") { if (!IsHex(p[2],96)) return null; }
            else if (!(IsHex(p[2],64) || IsHex(p[2],96))) return null;
            return p[0]; // Never returns client random, secret, arbitrary line or path.
        }
        public static KeylogSummary ParseBytes(byte[] bytes, int count, bool truncated) {
            if (bytes == null || count < 0 || count > bytes.Length || count > MaxReadBytes) throw new ArgumentException("invalid_bound");
            KeylogSummary r = new KeylogSummary(); r.BytesObserved=count; r.ReadLimitHit=truncated;
            int start=0;
            for (int i=0; i<=count; i++) {
                bool final=(i==count);
                if (!final && bytes[i] != 10) continue;
                // A read capped in the middle of a line must not accept the partial tail.
                if (final && truncated) break;
                int n=i-start;
                if (n>0 && bytes[start+n-1]==13) n--;
                if (n>0) {
                    if (n>512) r.InvalidLines++;
                    else {
                        string s=Encoding.ASCII.GetString(bytes,start,n).Trim();
                        if (s.Length>0 && !s.StartsWith("#",StringComparison.Ordinal)) {
                            string label=GetLabel(s);
                            if (label==null) r.InvalidLines++;
                            else { r.ValidLines++; if (!r.Labels.ContainsKey(label)) r.Labels[label]=0; r.Labels[label]++; }
                        }
                    }
                }
                start=i+1;
            }
            r.State=r.ValidLines>0 ? "keylog_format_lines_observed" : "no_usable_keylog_observed";
            return r;
        }
        public static KeylogSummary ReadSummary(string path) {
            if (!File.Exists(path)) return new KeylogSummary {State="keylog_file_not_observed"};
            try {
                using (FileStream f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)) {
                    byte[] b=new byte[MaxReadBytes+1]; int n=0;
                    while(n<b.Length) { int k=f.Read(b,n,b.Length-n); if(k==0) break; n+=k; }
                    return ParseBytes(b,Math.Min(n,MaxReadBytes),n>MaxReadBytes);
                }
            } catch (UnauthorizedAccessException) { return new KeylogSummary {State="keylog_read_denied"}; }
              catch (IOException) { return new KeylogSummary {State="keylog_read_io_failed"}; }
        }
        public static string HashFile(string path) {
            using(FileStream f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))
            using(SHA256 h=SHA256.Create()) { return BitConverter.ToString(h.ComputeHash(f)).Replace("-", "").ToLowerInvariant(); }
        }
        public static int SelfTest() {
            int checks=0;
            Action<bool> ok=delegate(bool test){checks++;if(!test)throw new Exception("self_test_"+checks);};
            string random=new string('a',64), secret=new string('b',96);
            ok(GetLabel("CLIENT_RANDOM "+random+" "+secret)=="CLIENT_RANDOM");
            ok(GetLabel("SERVER_TRAFFIC_SECRET_0 "+random+" "+new string('c',64))=="SERVER_TRAFFIC_SECRET_0");
            ok(GetLabel("CLIENT_HANDSHAKE_TRAFFIC_SECRET "+random+" "+secret)=="CLIENT_HANDSHAKE_TRAFFIC_SECRET");
            ok(GetLabel("UNKNOWN "+random+" "+secret)==null);
            ok(GetLabel("CLIENT_RANDOM "+new string('x',64)+" "+secret)==null);
            ok(GetLabel("CLIENT_RANDOM "+random+" "+new string('c',64))==null);
            ok(GetLabel("CLIENT_RANDOM "+random+" "+secret+" EXTRA")==null);
            ok(GetLabel(new string('x',513))==null);
            ok(GetLabel(null)==null);
            ok(GetLabel("client_random "+random+" "+secret)==null);
            ok(GetLabel("CLIENT_RANDOM\t"+random+"\t"+secret)=="CLIENT_RANDOM");
            byte[] bytes=Encoding.ASCII.GetBytes("# comment\r\nCLIENT_RANDOM "+random+" "+secret+"\ninvalid\n");
            KeylogSummary r=ParseBytes(bytes,bytes.Length,false);
            ok(r.ValidLines==1 && r.InvalidLines==1 && r.Labels.Count==1);
            ok(r.State=="keylog_format_lines_observed" && !r.ReadLimitHit);
            ok(ParseBytes(new byte[0],0,false).State=="no_usable_keylog_observed");
            bytes=Encoding.ASCII.GetBytes("CLIENT_RANDOM "+random+" "+secret);
            ok(ParseBytes(bytes,bytes.Length,false).ValidLines==1);
            ok(ParseBytes(bytes,bytes.Length,true).ValidLines==0);
            bytes=Encoding.ASCII.GetBytes("CLIENT_RANDOM "+random+" "+secret+"\n");
            ok(ParseBytes(bytes,bytes.Length,true).ValidLines==1);
            bool threw=false;try{ParseBytes(bytes,bytes.Length+1,false);}catch(ArgumentException){threw=true;}ok(threw);
            byte[] huge=new byte[MaxReadBytes+1];threw=false;try{ParseBytes(huge,huge.Length,false);}catch(ArgumentException){threw=true;}ok(threw);
            string temp=Path.Combine(Path.GetTempPath(),"wow-probe-test-"+Guid.NewGuid().ToString("N"));
            try {
                ok(ReadSummary(temp).State=="keylog_file_not_observed");
                File.WriteAllBytes(temp,bytes); string before=HashFile(temp); r=ReadSummary(temp);
                ok(r.ValidLines==1 && HashFile(temp)==before);
                File.WriteAllBytes(temp,huge);r=ReadSummary(temp);ok(r.ReadLimitHit && r.BytesObserved==MaxReadBytes);
                ok(Core.HashFile(temp).Length==64);
            } finally {if(File.Exists(temp))File.Delete(temp);}
            return checks;
        }
    }
}
