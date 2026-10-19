using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Collections.Generic;
public sealed class FlowLabServer : IDisposable {
 readonly TcpListener listener;readonly Thread accept;readonly object gate=new object();readonly Dictionary<string,long> bytes=new Dictionary<string,long>();readonly List<TcpClient> clients=new List<TcpClient>();volatile bool stopped;
 public int Port {get{return ((IPEndPoint)listener.LocalEndpoint).Port;}}
 public FlowLabServer(bool ipv6){listener=new TcpListener(ipv6?IPAddress.IPv6Loopback:IPAddress.Loopback,0);if(ipv6)listener.Server.DualMode=false;listener.Start(8);accept=new Thread(Accept);accept.IsBackground=true;accept.Start();}
 static bool Hex(string s){if(s==null||s.Length!=32)return false;foreach(char c in s)if(!(c>='0'&&c<='9')&&!(c>='a'&&c<='f'))return false;return true;}
 static string Line(NetworkStream stream){var b=new StringBuilder();for(int i=0;i<34;i++){int c=stream.ReadByte();if(c<0)throw new IOException();if(c==10)return b.ToString();b.Append((char)c);}throw new IOException();}
 static void Reply(NetworkStream s,string line){byte[] b=Encoding.ASCII.GetBytes(line+"\n");s.Write(b,0,b.Length);}
 void Accept(){try{while(!stopped){var c=listener.AcceptTcpClient();lock(gate){if(clients.Count>=16){c.Close();continue;}clients.Add(c);}var t=new Thread(()=>Serve(c));t.IsBackground=true;t.Start();}}catch{}}
 void Serve(TcpClient c){try{using(c){c.NoDelay=true;var s=c.GetStream();string tag=Line(s);if(!Hex(tag))return;lock(gate){if(bytes.ContainsKey(tag))return;bytes[tag]=0;}Reply(s,"READY");var line=new StringBuilder();while(!stopped){int next=s.ReadByte();if(next<0)break;lock(gate){bytes[tag]++;if(bytes[tag]>4096)break;}if(next==10){string token=line.ToString();if(!Hex(token))break;Reply(s,token);line.Clear();}else{if(line.Length>=32)break;line.Append((char)next);}}}}catch{}}
 public long Bytes(string tag){lock(gate){long n;return bytes.TryGetValue(tag,out n)?n:-1;}}
 public void Dispose(){stopped=true;listener.Stop();lock(gate){foreach(var c in clients)try{c.Close();}catch{}}accept.Join(1000);}
}
