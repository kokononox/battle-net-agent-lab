"""Bounded PE table reads only; never load/execute the inspected image."""
import mmap
import struct

MODULES=set('''libgnutls-30.dll gnutls.dll libssl-3.dll libcrypto-3.dll qt6network.dll qt5network.dll libcef.dll chrome_elf.dll chrome.dll msedge_elf.dll libssl-3-x64.dll libssl-1_1-x64.dll libssl.dll ssleay32.dll libcrypto-3-x64.dll libcrypto-1_1-x64.dll libcrypto.dll libeay32.dll winhttp.dll wininet.dll secur32.dll sspicli.dll schannel.dll ws2_32.dll crypt32.dll bcrypt.dll ncrypt.dll nss3.dll nspr4.dll softokn3.dll libcurl.dll curl.dll libnghttp2.dll libquiche.dll msquic.dll cronet.dll'''.split())
SYMBOLS=set('''SSL_write SSL_write_ex SSL_read SSL_read_ex SSL_get_fd SSL_get_version SSL_CTX_new BIO_write PR_Write PR_Send gnutls_record_send curl_easy_perform curl_multi_perform nghttp2_session_send nghttp2_submit_request WinHttpConnect WinHttpOpenRequest WinHttpSendRequest WinHttpWriteData WinHttpReceiveResponse WinHttpReadData WinHttpWebSocketSend WinHttpOpen HttpSendRequestA HttpSendRequestW InternetWriteFile InternetConnectA InternetConnectW HttpOpenRequestA HttpOpenRequestW EncryptMessage InitializeSecurityContextA InitializeSecurityContextW AcquireCredentialsHandleA AcquireCredentialsHandleW BCryptEncrypt NCryptEncrypt send WSASend WSASendTo connect WSAConnect WSAIoctl cef_version_info cef_initialize cef_browser_host_create_browser MsQuicOpenVersion'''.split())
CANON={s.lower():s for s in SYMBOLS}

def canonical_symbol(s):
    if s.startswith('_'):s=s[1:]
    s=s.split('@',1)[0]
    return CANON.get(s.lower())

class PE:
    def __init__(self,data):
        self.d=data;self.n=len(data);self.limited=False;self.thunks=0
        if self.n>1024**3 or self.n<128 or self.read(0,2)!=b'MZ':raise ValueError('not_pe')
        pe=self.u32(60)
        if pe>16*1024**2 or self.read(pe,4)!=b'PE\0\0':raise ValueError('pe_header')
        sections=self.u16(pe+6);opsize=self.u16(pe+20);op=pe+24
        if not 1<=sections<=96 or not 96<=opsize<=4096:raise ValueError('pe_header_bounds')
        self.read(op,opsize);magic=self.u16(op)
        if magic==0x20b:self.width=8;dirs=op+112;nd=op+108
        elif magic==0x10b:self.width=4;dirs=op+96;nd=op+92
        else:raise ValueError('pe_optional_magic')
        count=min(self.u32(nd),16)
        if dirs+count*8>op+opsize:raise ValueError('directory_bounds')
        self.directories=[(self.u32(dirs+i*8),self.u32(dirs+i*8+4)) for i in range(count)]
        self.headers=self.u32(op+60);self.sections=[]
        for i in range(sections):
            s=op+opsize+40*i;self.read(s,40)
            vs,va,rawsize,raw=struct.unpack('<IIII',self.read(s+8,16))
            self.sections.append((va,vs,rawsize,raw))
    def read(self,p,n):
        if type(p) is not int or type(n) is not int or p<0 or n<0 or p+n>self.n:raise ValueError('file_bounds')
        return self.d[p:p+n]
    def u16(self,p):return struct.unpack('<H',self.read(p,2))[0]
    def u32(self,p):return struct.unpack('<I',self.read(p,4))[0]
    def rva(self,r,n=1):
        if not 0<=r<=0xffffffff or n<0:raise ValueError('rva_bounds')
        if r<self.headers and r+n<=min(self.headers,self.n):return r
        for va,vs,size,raw in self.sections:
            delta=r-va
            if 0<=delta and delta+n<=size and delta<max(vs,size):
                self.read(raw+delta,n);return raw+delta
        raise ValueError('unmapped_rva')
    def string(self,r):
        p=self.rva(r);chunk=self.read(p,min(513,self.n-p));end=chunk.find(b'\0')
        if end<0 or end>512:raise ValueError('pe_string_bounds')
        # Verify the string does not cross the file-backed section boundary.
        self.rva(r,end+1)
        try:return chunk[:end].decode('ascii')
        except UnicodeError:raise ValueError('pe_string_encoding')
    def directory(self,i):return self.directories[i] if len(self.directories)>i else (0,0)
    def exports(self):
        r,size=self.directory(0)
        if not r:return []
        p=self.rva(r,40);number=self.u32(p+24);names=self.u32(p+32)
        if number>65536:self.limited=True;number=65536
        out=set()
        for i in range(number):
            name=self.string(self.u32(self.rva(names+i*4,4)));known=canonical_symbol(name)
            if known:out.add(known)
        return sorted(out)
    def imports(self):
        r,size=self.directory(1)
        if not r:return [],[]
        if size<20:raise ValueError('import_directory_size')
        apis=set();libraries=set();ended=False
        for i in range(min(size//20,256)):
            p=self.rva(r+i*20,20);values=struct.unpack('<IIIII',self.read(p,20))
            if not any(values):ended=True;break
            original,_,_,name,first=values
            dll=self.string(name).lower()
            if dll in MODULES:libraries.add(dll)
            table=original or first
            if not table:raise ValueError('import_thunk_missing')
            finished=False
            for j in range(8192):
                self.thunks+=1
                if self.thunks>32768:self.limited=True;return sorted(apis),sorted(libraries)
                p=self.rva(table+j*self.width,self.width);v=int.from_bytes(self.read(p,self.width),'little')
                if not v:finished=True;break
                if v&(1<<(8*self.width-1)):continue
                if v>0xffffffff:raise ValueError('import_name_rva')
                symbol=canonical_symbol(self.string(v+2))
                if symbol:apis.add(symbol)
            if not finished:self.limited=True
        if not ended:self.limited=True
        return sorted(apis),sorted(libraries)
    def result(self):
        exports=self.exports();imports,libraries=self.imports();delay=self.directory(13)
        return {'status':'parsed','exported_api_hints':exports,'imported_api_hints':imports,
            'imported_library_categories':libraries,'table_limit_hit':self.limited,
            'delay_imports_present':bool(delay[0]),'delay_imports_inspected':False,
            'static_linked_or_dynamic_resolved_apis_excluded':False,'library_presence_proves_use':False}

def inspect(path):
    try:
        with path.open('rb') as f:
            with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:return PE(data).result()
    except (OSError,ValueError,struct.error,OverflowError):
        return {'status':'unreadable_or_unrecognized_pe','exported_api_hints':[],
            'imported_api_hints':[],'imported_library_categories':[],'table_limit_hit':False,
            'delay_imports_present':None,'delay_imports_inspected':False,
            'static_linked_or_dynamic_resolved_apis_excluded':False,'library_presence_proves_use':False}
