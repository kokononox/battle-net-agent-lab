using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
public static class FlowLabProbe {
 static bool Hex(string s){if(s==null||s.Length!=32)return false;foreach(char c in s)if(!(c>='0'&&c<='9')&&!(c>='a'&&c<='f'))return false;return true;}
 static string Line(NetworkStream s){var b=new StringBuilder();for(int i=0;i<34;i++){int c=s.ReadByte();if(c<0)throw new IOException();if(c==10)return b.ToString();b.Append((char)c);}throw new IOException();}
 static void Send(NetworkStream s,string line){byte[] b=Encoding.ASCII.GetBytes(line+"\n");s.Write(b,0,b.Length);}
 public static int Main(string[] args){IPAddress ip;int port;if(args.Length!=3||!IPAddress.TryParse(args[0],out ip)||!(ip.Equals(IPAddress.Loopback)||ip.Equals(IPAddress.IPv6Loopback))||!int.TryParse(args[1],out port)||port<1024||port>65535||!Hex(args[2]))return 3;
  try{using(var c=new TcpClient(ip.AddressFamily)){c.NoDelay=true;var connect=c.ConnectAsync(ip,port);if(!connect.Wait(3000)){Console.WriteLine("CONNECT_FAILED");return 2;}var s=c.GetStream();s.ReadTimeout=2500;s.WriteTimeout=2500;Send(s,args[2]);if(Line(s)!="READY")return 2;Console.WriteLine("READY");bool dead=false;var input=new StreamReader(Console.OpenStandardInput(),new UTF8Encoding(false),true);for(;;){string command=input.ReadLine();if(command==null||command=="QUIT")break;if(!Hex(command))return 3;if(dead){Console.WriteLine("BLOCKED");continue;}try{Send(s,command);if(Line(s)!=command)throw new IOException();Console.WriteLine("OK");}catch{dead=true;Console.WriteLine("BLOCKED");}}return 0;}}
  catch{Console.WriteLine("CONNECT_FAILED");return 2;}}
}
