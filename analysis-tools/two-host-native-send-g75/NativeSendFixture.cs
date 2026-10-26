using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
public class NativeSendFixture {
 [StructLayout(LayoutKind.Sequential)]struct Addr{public ushort family;public ushort port;public uint address;[MarshalAs(UnmanagedType.ByValArray,SizeConst=8)]public byte[] zero;}
 [StructLayout(LayoutKind.Sequential)]struct Buffer{public uint length;public IntPtr data;}
 [DllImport("ws2_32.dll")]static extern int WSAStartup(ushort v,[Out]byte[] d);
 [DllImport("ws2_32.dll")]static extern IntPtr socket(int af,int type,int protocol);
 [DllImport("ws2_32.dll")]static extern int connect(IntPtr s,ref Addr a,int n);
 [DllImport("ws2_32.dll")]static extern int send(IntPtr s,IntPtr b,int n,int flags);
 [DllImport("ws2_32.dll")]static extern int WSASend(IntPtr s,[In]Buffer[] b,uint count,out uint sent,uint flags,IntPtr ov,IntPtr cb);
 [DllImport("ws2_32.dll")]static extern int WSAGetLastError();
 [DllImport("ws2_32.dll")]static extern int closesocket(IntPtr s);
 [DllImport("ws2_32.dll")]static extern int WSACleanup();
 static bool Denied(int result){return result==-1&&WSAGetLastError()==10013;}
 public static int Main(string[] args){
  int port;if(args.Length!=5||!Int32.TryParse(args[0],out port)||port<1||port>65535)return 2;
  byte[] raw=File.ReadAllBytes(args[1]);string mode=args[2];bool allowed=args[3]=="allow";string marker=args[4];
  if(WSAStartup(0x202,new byte[512])!=0)return 3;
  IntPtr s=socket(2,1,6);if(s==new IntPtr(-1))return 4;
  IntPtr p=Marshal.AllocHGlobal(raw.Length);Thread mutator=null;
  try{
   Marshal.Copy(raw,0,p,raw.Length);
   Addr a=new Addr{family=2,port=(ushort)(((port&255)<<8)|(port>>8)),address=0x0100007f,zero=new byte[8]};
   if(connect(s,ref a,16)!=0)return 5;
   if(mode=="mutate"){
    mutator=new Thread(delegate(){
     DateTime deadline=DateTime.UtcNow.AddSeconds(4);
     while(!File.Exists(marker)&&DateTime.UtcNow<deadline)Thread.Sleep(5);
     if(!File.Exists(marker))return;
     byte[] poison=new byte[raw.Length];for(int i=0;i<poison.Length;i++)poison[i]=(byte)'P';
     Marshal.Copy(poison,0,p,poison.Length);File.WriteAllText(marker+".done","mutated");
    });mutator.IsBackground=true;mutator.Start();
   }
   if(mode=="wsa"){
    uint n;int r=WSASend(s,new Buffer[]{new Buffer{length=(uint)raw.Length,data=p}},1,out n,0,IntPtr.Zero,IntPtr.Zero);
    return Denied(r)&&n==0?0:6;
   }
   if(mode=="split"){
    int cut=9;int one=send(s,p,cut,0);bool denied=Denied(one);
    int two=send(s,IntPtr.Add(p,cut),raw.Length-cut,0);
    return denied&&Denied(two)?0:7;
   }
   int result=send(s,p,raw.Length,mode=="flags"?1:0);
   bool ok=allowed?result==raw.Length:Denied(result);
   if(mode=="tail"){
    byte[] tail=Encoding.ASCII.GetBytes("PRIVATE_SENTINEL");IntPtr t=Marshal.AllocHGlobal(tail.Length);
    try{Marshal.Copy(tail,0,t,tail.Length);ok=ok&&Denied(send(s,t,tail.Length,0));}finally{Marshal.FreeHGlobal(t);}
   }
   if(mutator!=null){mutator.Join(1000);ok=ok&&File.Exists(marker+".done");}
   return ok?0:8;
  }finally{
   if(mutator!=null)mutator.Join(1000);
   closesocket(s);WSACleanup();Marshal.FreeHGlobal(p);
  }
 }
}
