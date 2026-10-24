// Authenticode trust policy verification, with publisher from THAT verified signer.
// No UI, certificate-store modification, cache-only/no-revocation fallback or raw subject export.
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class RefusedSignature {
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    struct FileInfoNative { public uint cbStruct; [MarshalAs(UnmanagedType.LPWStr)] public string path;
        public IntPtr file; public IntPtr subject; }
    [StructLayout(LayoutKind.Sequential)]
    struct TrustData { public uint cbStruct; public IntPtr policyCallback,sipClient;
        public uint uiChoice,revocationChecks,unionChoice; public IntPtr fileInfo;
        public uint stateAction; public IntPtr stateData,urlReference; public uint providerFlags,uiContext;
        public IntPtr signatureSettings; }
    [StructLayout(LayoutKind.Sequential)]
    struct Signer { public uint cbStruct,timeLow,timeHigh,certificateCount; public IntPtr certificates;
        public uint signerType; public IntPtr signerInfo; public uint error,counterSignerCount;
        public IntPtr counterSigners,chainContext; }
    [StructLayout(LayoutKind.Sequential)]
    struct CertificatePrefix { public uint cbStruct; public IntPtr certificate;
        public int commercial,trustedRoot,selfSigned,testCertificate; public uint revokedReason,confidence,error; }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll",ExactSpelling=true)]
    static extern int WinVerifyTrust(IntPtr window,ref Guid action,ref TrustData data);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll",ExactSpelling=true)]
    static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll",ExactSpelling=true)]
    static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provider,uint index,[MarshalAs(UnmanagedType.Bool)]bool counterSigner,uint counterIndex);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("crypt32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    static extern uint CertGetNameStringW(IntPtr certificate,uint type,uint flags,IntPtr typeParameters,[Out]StringBuilder name,uint characters);

    public static int Main() {
        try {
            var r=Verify(Environment.GetEnvironmentVariable("BNET_READ_ONLY_SIGNATURE_PATH"));
            Console.WriteLine("{\"trust_status\":"+((int)r["trust_status"]).ToString(System.Globalization.CultureInfo.InvariantCulture)+",\"publisher_class\":\""+(string)r["publisher_class"]+"\"}");
            return 0;
        } catch { return 2; }
    }
    public static Dictionary<string,object> Abi() {
        return new Dictionary<string,object> { {"pointer_bytes",IntPtr.Size},
            {"trust_data_bytes",Marshal.SizeOf(typeof(TrustData))},{"file_info_bytes",Marshal.SizeOf(typeof(FileInfoNative))},
            {"signer_bytes",Marshal.SizeOf(typeof(Signer))},{"certificate_prefix_bytes",Marshal.SizeOf(typeof(CertificatePrefix))} };
    }
    static string PublisherClass(IntPtr state) {
        if(state==IntPtr.Zero) return "unverified";
        var provider=WTHelperProvDataFromStateData(state); if(provider==IntPtr.Zero) return "unverified";
        var pointer=WTHelperGetProvSignerFromChain(provider,0,false,0); if(pointer==IntPtr.Zero) return "unverified";
        var signer=(Signer)Marshal.PtrToStructure(pointer,typeof(Signer));
        if(signer.cbStruct<Marshal.SizeOf(typeof(Signer)) || signer.error!=0 || signer.certificateCount==0 || signer.certificateCount>128 || signer.certificates==IntPtr.Zero) return "unverified";
        var certificate=(CertificatePrefix)Marshal.PtrToStructure(signer.certificates,typeof(CertificatePrefix));
        if(certificate.cbStruct<Marshal.SizeOf(typeof(CertificatePrefix)) || certificate.certificate==IntPtr.Zero || certificate.error!=0) return "unverified";
        uint length=CertGetNameStringW(certificate.certificate,4,0,IntPtr.Zero,null,0);
        if(length<2 || length>512) return "unverified";
        var name=new StringBuilder((int)length);
        if(CertGetNameStringW(certificate.certificate,4,0,IntPtr.Zero,name,length)!=length) return "unverified";
        var publishers=new HashSet<string>(StringComparer.Ordinal) { "Blizzard Entertainment, Inc.","Blizzard Entertainment, Inc",
            "Blizzard Entertainment Inc.","Blizzard Entertainment" };
        if(publishers.Contains(name.ToString())) return "blizzard";
        var microsoft=new HashSet<string>(StringComparer.Ordinal) { "Microsoft Corporation", "Microsoft Windows", "Microsoft Windows Publisher" };
        return microsoft.Contains(name.ToString()) ? "microsoft" : "other_verified";
    }
    public static Dictionary<string,object> Verify(string path) {
        if(String.IsNullOrEmpty(path) || !Path.IsPathRooted(path)) throw new ArgumentException();
        var action=new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
        using(var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
            var info=new FileInfoNative { cbStruct=(uint)Marshal.SizeOf(typeof(FileInfoNative)),path=path,
                file=stream.SafeFileHandle.DangerousGetHandle(),subject=IntPtr.Zero };
            IntPtr memory=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FileInfoNative)));
            var data=new TrustData { cbStruct=(uint)Marshal.SizeOf(typeof(TrustData)),uiChoice=2,
                revocationChecks=1,unionChoice=1,fileInfo=memory,stateAction=1,
                providerFlags=0x2080,uiContext=0 }; // chain revocation excluding root + disable MD2/MD4
            bool initialized=false,attempted=false;
            try {
                Marshal.StructureToPtr(info,memory,false); initialized=true;
                attempted=true;
                int status=WinVerifyTrust(new IntPtr(-1),ref action,ref data);
                // ONLY zero means trusted. Never use HRESULT SUCCEEDED or publisher strings from the file.
                string publisher="unverified";
                if(status==0) publisher=PublisherClass(data.stateData);
                return new Dictionary<string,object> { {"trust_status",status},{"publisher_class",publisher} };
            } finally {
                try {
                    if(attempted) { data.stateAction=2; WinVerifyTrust(new IntPtr(-1),ref action,ref data); }
                } finally {
                    if(initialized) Marshal.DestroyStructure(memory,typeof(FileInfoNative));
                    Marshal.FreeHGlobal(memory);
                }
            }
        }
    }
}
