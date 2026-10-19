using System;
using System.Net;
using System.Net.Sockets;
public static class GuardNetworkProbe {
 public static int Main(string[] args) {
  IPAddress ip; int port;
  if(args.Length!=2 || !IPAddress.TryParse(args[0],out ip) || ip.AddressFamily!=AddressFamily.InterNetwork || !int.TryParse(args[1],out port) || port!=443) return 3;
  using(var client=new TcpClient(AddressFamily.InterNetwork)) {
   try { var task=client.ConnectAsync(ip,port); if(!task.Wait(4000))return 2;return client.Connected?0:2; }
   catch { return 2; }
  }
 }
}
