using System;
using System.Net;
using System.Net.Sockets;
public static class Probe {
 public static int Main(string[] args) {
  if(args.Length!=2)return 3;
  try { var ip=IPAddress.Parse(args[0]);using(var c=new TcpClient(ip.AddressFamily)) {
   var ar=c.BeginConnect(ip,int.Parse(args[1]),null,null);
   if(!ar.AsyncWaitHandle.WaitOne(1500))return 2;
   c.EndConnect(ar);return c.Connected?0:2;
  }}catch{return 2;}
 }
}
