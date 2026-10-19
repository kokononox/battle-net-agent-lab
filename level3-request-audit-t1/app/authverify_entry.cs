using System;
public static class AuthVerifyEntry {
    public static int Main(string[] args) {
        try {
            if(args.Length!=1) return 2;
            var r=AuthenticodeNative.Verify(args[0]);
            bool valid=(int)r["trust_status"]==0;
            bool publisher=valid && (bool)r["expected_blizzard_publisher"];
            Console.Write("{\"valid\":"+(valid?"true":"false")+",\"blizzard\":"+(publisher?"true":"false")+",\"status\":\""+(valid?"Valid":"NotTrusted")+"\"}");
            return 0;
        } catch { return 3; }
    }
}
