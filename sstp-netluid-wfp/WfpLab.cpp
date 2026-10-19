// LAB ONLY: restrictive rules for one randomly named TCP fixture, not a host kill switch.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <ipifcons.h>
#include <netioapi.h>
#include <objbase.h>
#include <string>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <cwctype>
#include <cerrno>
#include <initializer_list>
#include <utility>
#pragma comment(lib,"Fwpuclnt.lib")
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Ole32.lib")
static const GUID EmptyGuid={};
static const wchar_t* Label=L"sstp-netluid-lab-v1";
static void Require(bool ok,int line) { if(!ok) { std::cout<<"wfp_assert_line_"<<line<<std::endl;throw DWORD(ERROR_INVALID_DATA); } }
#define Need(ok) Require((ok),__LINE__)
static void Fields(std::initializer_list<std::pair<bool,const char*>> fields){bool pass=true;for(const auto& f:fields)if(!f.first){std::cout<<"wfp_field_"<<f.second<<std::endl;pass=false;}if(!pass)throw DWORD(ERROR_INVALID_DATA);}
static void Ok(DWORD rc) { if(rc!=ERROR_SUCCESS) throw rc; }
static bool Eq(const GUID& a,const GUID& b) { return InlineIsEqualGUID(a,b)!=0; }
static bool Text(const wchar_t* a,const wchar_t* b) { return a && b && wcscmp(a,b)==0; }
struct Mem { void* p=nullptr; ~Mem(){if(p) FwpmFreeMemory0(&p);} };
struct Engine { HANDLE h=nullptr; bool tx=false;
 Engine(){FWPM_SESSION0 s={};s.displayData.name=const_cast<wchar_t*>(Label);Ok(FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,&s,&h));}
 ~Engine(){if(tx)FwpmTransactionAbort0(h);if(h)FwpmEngineClose0(h);}
 void Begin(){Ok(FwpmTransactionBegin0(h,0));tx=true;}
 void Commit(){Ok(FwpmTransactionCommit0(h));tx=false;}
};
struct Plan { GUID keys[5]={}; UINT64 luid=0;UINT32 ip=0;std::wstring app;Mem appid; };
static bool Blob(const FWP_BYTE_BLOB& a,const FWP_BYTE_BLOB& b){return a.size==b.size && (a.size==0 || (a.data && b.data && memcmp(a.data,b.data,a.size)==0));}
static FWP_BYTE_BLOB Marker(const Plan& p){FWP_BYTE_BLOB b={sizeof(GUID),reinterpret_cast<UINT8*>(const_cast<GUID*>(&p.keys[0]))};return b;}
static void LoadPlan(int argc,wchar_t** argv,Plan& p){
 Need(argc==10 || argc==11);
 for(int i=0;i<5;i++){Need(SUCCEEDED(CLSIDFromString(argv[2+i],&p.keys[i])));Need(!Eq(p.keys[i],EmptyGuid));for(int j=0;j<i;j++)Need(!Eq(p.keys[i],p.keys[j]));}
 std::wstring n=argv[7];Need(!n.empty() && n.size()<=20);for(auto c:n)Need(c>=L'0'&&c<=L'9');errno=0;wchar_t* end=nullptr;p.luid=_wcstoui64(n.c_str(),&end,10);Need(errno==0 && end && *end==0 && p.luid!=0);
 IN_ADDR ip={};Need(InetPtonW(AF_INET,argv[8],&ip)==1);p.ip=ntohl(ip.S_un.S_addr);Need(p.ip!=0 && p.ip!=0xffffffff && (p.ip>>24)!=127 && (p.ip>>24)<224);
 p.app=argv[9];Need(p.app.size()>3 && p.app[1]==L':' && p.app[2]==L'\\');size_t sep=p.app.find_last_of(L"\\/");Need(sep!=std::wstring::npos);std::wstring base=p.app.substr(sep+1);const std::wstring prefix=L"sstp-luid-probe-";Need(base.size()==prefix.size()+32+4 && base.compare(0,prefix.size(),prefix)==0 && base.substr(base.size()-4)==L".exe");for(size_t i=prefix.size();i<prefix.size()+32;i++)Need((base[i]>=L'0'&&base[i]<=L'9')||(base[i]>=L'a'&&base[i]<=L'f'));
 DWORD attr=GetFileAttributesW(p.app.c_str());Need(attr!=INVALID_FILE_ATTRIBUTES && !(attr&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)));
 Ok(FwpmGetAppIdFromFileName0(p.app.c_str(),reinterpret_cast<FWP_BYTE_BLOB**>(&p.appid.p)));
}
static FWPM_PROVIDER0 Provider(const Plan& p){FWPM_PROVIDER0 x={};x.providerKey=p.keys[0];x.displayData.name=const_cast<wchar_t*>(Label);x.displayData.description=const_cast<wchar_t*>(Label);x.flags=FWPM_PROVIDER_FLAG_PERSISTENT;x.providerData=Marker(p);return x;}
static FWPM_SUBLAYER0 Sub(const Plan& p){FWPM_SUBLAYER0 x={};x.subLayerKey=p.keys[1];x.displayData.name=const_cast<wchar_t*>(Label);x.displayData.description=const_cast<wchar_t*>(Label);x.flags=FWPM_SUBLAYER_FLAG_PERSISTENT;x.providerKey=const_cast<GUID*>(&p.keys[0]);x.providerData=Marker(p);x.weight=0x5a23;return x;}
struct Filter {
 FWPM_FILTER0 f={};FWPM_FILTER_CONDITION0 c[2]={};UINT64 weight=0xf000000000000001ULL;UINT64 luid;
 Filter(const Plan& p,int k):luid(p.luid){
 f.filterKey=p.keys[k+2];f.displayData.name=const_cast<wchar_t*>(Label);f.displayData.description=const_cast<wchar_t*>(Label);f.flags=FWPM_FILTER_FLAG_PERSISTENT;f.providerKey=const_cast<GUID*>(&p.keys[0]);f.providerData=Marker(p);f.layerKey=(k==2?FWPM_LAYER_ALE_AUTH_CONNECT_V6:FWPM_LAYER_ALE_AUTH_CONNECT_V4);f.subLayerKey=p.keys[1];f.weight.type=FWP_UINT64;f.weight.uint64=&weight;f.action.type=FWP_ACTION_BLOCK;f.numFilterConditions=(k==2?1u:2u);f.filterCondition=c;
 c[0].fieldKey=FWPM_CONDITION_ALE_APP_ID;c[0].matchType=FWP_MATCH_EQUAL;c[0].conditionValue.type=FWP_BYTE_BLOB_TYPE;c[0].conditionValue.byteBlob=static_cast<FWP_BYTE_BLOB*>(p.appid.p);
 if(k==0){c[1].fieldKey=FWPM_CONDITION_IP_LOCAL_INTERFACE;c[1].matchType=FWP_MATCH_NOT_EQUAL;c[1].conditionValue.type=FWP_UINT64;c[1].conditionValue.uint64=&luid;}
 if(k==1){c[1].fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS;c[1].matchType=FWP_MATCH_NOT_EQUAL;c[1].conditionValue.type=FWP_UINT32;c[1].conditionValue.uint32=p.ip;}
 }
 Filter(const Filter&)=delete;Filter& operator=(const Filter&)=delete;
};
static void CheckProvider(const Plan& p,const FWPM_PROVIDER0& x){auto y=Provider(p);Need(Eq(x.providerKey,y.providerKey)&&Text(x.displayData.name,Label)&&Text(x.displayData.description,Label)&&x.flags==y.flags&&Blob(x.providerData,y.providerData)&&x.serviceName==nullptr);}
static void CheckSub(const Plan& p,const FWPM_SUBLAYER0& x){auto y=Sub(p);if(x.weight!=y.weight)std::cout<<"wfp_sub_weight_observed_"<<x.weight<<"_expected_"<<y.weight<<std::endl;Fields({
 {Eq(x.subLayerKey,y.subLayerKey),"sub_key"},{Text(x.displayData.name,Label),"sub_name"},{Text(x.displayData.description,Label),"sub_description"},
 {x.flags==y.flags,"sub_flags"},{x.providerKey&&Eq(*x.providerKey,p.keys[0]),"sub_provider"},{Blob(x.providerData,y.providerData),"sub_data"},{x.weight==y.weight,"sub_weight"}});}
static void CheckFilter(const Plan& p,int k,const FWPM_FILTER0& x){Filter y(p,k);const auto& f=y.f;
 Fields({{Eq(x.filterKey,f.filterKey),"filter_key"},{Text(x.displayData.name,Label),"filter_name"},{Text(x.displayData.description,Label),"filter_description"},
 {x.flags==f.flags,"filter_flags"},{x.providerKey&&Eq(*x.providerKey,p.keys[0]),"filter_provider"},{Blob(x.providerData,f.providerData),"filter_data"},
 {Eq(x.layerKey,f.layerKey),"filter_layer"},{Eq(x.subLayerKey,f.subLayerKey),"filter_sub"},
 {x.weight.type==FWP_UINT64&&x.weight.uint64&&*x.weight.uint64==y.weight,"filter_weight"},{x.action.type==FWP_ACTION_BLOCK,"filter_action"},
 {Eq(x.action.filterType,EmptyGuid),"filter_action_guid"},{x.rawContext==0,"filter_context"},{x.reserved==nullptr,"filter_reserved"},{x.filterId!=0,"filter_runtime_id"},
 {x.numFilterConditions==f.numFilterConditions&&x.filterCondition,"filter_conditions"}});
 Need(x.effectiveWeight.type==FWP_UINT64&&x.effectiveWeight.uint64);
 bool seen[2]={false,false};for(UINT32 i=0;i<x.numFilterConditions;i++){const auto& a=x.filterCondition[i];int j=-1;for(UINT32 t=0;t<f.numFilterConditions;t++)if(Eq(a.fieldKey,y.c[t].fieldKey))j=static_cast<int>(t);Need(j>=0&&!seen[j]);seen[j]=true;const auto& b=y.c[j];Need(a.matchType==b.matchType&&a.conditionValue.type==b.conditionValue.type);
 if(b.conditionValue.type==FWP_BYTE_BLOB_TYPE)Need(a.conditionValue.byteBlob&&Blob(*a.conditionValue.byteBlob,*b.conditionValue.byteBlob));
 else if(b.conditionValue.type==FWP_UINT64)Need(a.conditionValue.uint64&&*a.conditionValue.uint64==*b.conditionValue.uint64);
 else Need(a.conditionValue.uint32==b.conditionValue.uint32);
 }
}
static bool Audit(Engine& e,const Plan& p){
 int found=0;Mem a,b;DWORD r=FwpmProviderGetByKey0(e.h,&p.keys[0],reinterpret_cast<FWPM_PROVIDER0**>(&a.p));if(r==ERROR_SUCCESS){found++;CheckProvider(p,*static_cast<FWPM_PROVIDER0*>(a.p));}else Need(r==static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND));
 r=FwpmSubLayerGetByKey0(e.h,&p.keys[1],reinterpret_cast<FWPM_SUBLAYER0**>(&b.p));if(r==ERROR_SUCCESS){found++;CheckSub(p,*static_cast<FWPM_SUBLAYER0*>(b.p));}else Need(r==static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND));
 UINT64 ids[3]={};for(int k=0;k<3;k++){Mem m;r=FwpmFilterGetByKey0(e.h,&p.keys[k+2],reinterpret_cast<FWPM_FILTER0**>(&m.p));if(r==ERROR_SUCCESS){found++;const auto& f=*static_cast<FWPM_FILTER0*>(m.p);CheckFilter(p,k,f);ids[k]=f.filterId;for(int j=0;j<k;j++)Need(ids[j]!=ids[k]);}else Need(r==static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND));}
 Need(found==0||found==5);return found==5;
}
static void RequireFreeWeight(Engine& e,const Plan& p){HANDLE eh=nullptr;Ok(FwpmSubLayerCreateEnumHandle0(e.h,nullptr,&eh));bool used=false;UINT32 total=0;try{for(;;){Mem m;UINT32 n=0;Ok(FwpmSubLayerEnum0(e.h,eh,64,reinterpret_cast<FWPM_SUBLAYER0***>(&m.p),&n));if(n==0)break;total+=n;Need(total<=4096);auto rows=static_cast<FWPM_SUBLAYER0**>(m.p);for(UINT32 i=0;i<n;i++)if(rows[i]->weight==Sub(p).weight)used=true;}Ok(FwpmSubLayerDestroyEnumHandle0(e.h,eh));eh=nullptr;}catch(...){if(eh)FwpmSubLayerDestroyEnumHandle0(e.h,eh);throw;}if(used){std::cout<<"wfp_requested_weight_in_use"<<std::endl;throw DWORD(ERROR_INVALID_DATA);}}
static void Crash(bool yes){if(yes)TerminateProcess(GetCurrentProcess(),73);}
static NET_LUID Luid(NET_IFINDEX index){NET_LUID l={};Ok(ConvertInterfaceIndexToLuid(index,&l));NET_IFINDEX back=0;Ok(ConvertInterfaceLuidToIndex(&l,&back));Need(back==index&&l.Value!=0);GUID g={};Ok(ConvertInterfaceLuidToGuid(&l,&g));MIB_IF_ROW2 row={};row.InterfaceLuid=l;Ok(GetIfEntry2(&row));Need(row.InterfaceIndex==index&&Eq(row.InterfaceGuid,g)&&row.OperStatus==IfOperStatusUp);return l;}
static void Identity(const wchar_t* remote){SOCKADDR_IN dst={};dst.sin_family=AF_INET;Need(InetPtonW(AF_INET,remote,&dst.sin_addr)==1);NET_IFINDEX ix=0;Ok(GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&dst),&ix));NET_LUID selected=Luid(ix);PMIB_IF_TABLE2 table=nullptr;Ok(GetIfTable2(&table));NET_IFINDEX loop=0;for(ULONG n=0;n<table->NumEntries;n++)if(table->Table[n].Type==IF_TYPE_SOFTWARE_LOOPBACK&&table->Table[n].OperStatus==IfOperStatusUp){Need(loop==0);loop=table->Table[n].InterfaceIndex;}FreeMibTable(table);Need(loop!=0);NET_LUID other=Luid(loop);Need(selected.Value!=other.Value);std::cout<<"{\"selected_luid\":\""<<selected.Value<<"\",\"loopback_luid\":\""<<other.Value<<"\",\"roundtrip\":true}"<<std::endl;}
int wmain(int argc,wchar_t** argv){try{WSADATA ws={};Ok(static_cast<DWORD>(WSAStartup(MAKEWORD(2,2),&ws)));Need(argc>=2);std::wstring cmd=argv[1];if(cmd==L"identity"){Need(argc==3);Identity(argv[2]);return 0;}
 Need(cmd==L"install"||cmd==L"audit"||cmd==L"remove");Plan p;LoadPlan(argc,argv,p);std::wstring fault=argc==11?argv[10]:L"none";Need(fault==L"none"||(cmd==L"install"&&(fault==L"abort-add"||fault==L"after-install-commit"))||(cmd==L"remove"&&(fault==L"abort-remove"||fault==L"after-remove-commit")));
 Engine e;if(cmd==L"audit"){bool installed=Audit(e,p);std::cout<<"{\"state\":\""<<(installed?"installed":"absent")<<"\",\"filters\":"<<(installed?3:0)<<",\"strict_readback\":true}"<<std::endl;return 0;}
 e.Begin();bool exists=Audit(e,p);
 if(cmd==L"install"&&!exists){RequireFreeWeight(e,p);auto provider=Provider(p);auto sub=Sub(p);Ok(FwpmProviderAdd0(e.h,&provider,nullptr));Ok(FwpmSubLayerAdd0(e.h,&sub,nullptr));for(int k=0;k<3;k++){Filter f(p,k);Ok(FwpmFilterAdd0(e.h,&f.f,nullptr,nullptr));if(k==0)Crash(fault==L"abort-add");}Need(Audit(e,p));}
 if(cmd==L"remove"&&exists){for(int k=0;k<3;k++){Ok(FwpmFilterDeleteByKey0(e.h,&p.keys[k+2]));if(k==0)Crash(fault==L"abort-remove");}Ok(FwpmSubLayerDeleteByKey0(e.h,&p.keys[1]));Ok(FwpmProviderDeleteByKey0(e.h,&p.keys[0]));Need(!Audit(e,p));}
 e.Commit();Crash(fault==L"after-install-commit"||fault==L"after-remove-commit");Need(Audit(e,p)==(cmd==L"install"));std::cout<<"{\"mutation_verified\":true}"<<std::endl;return 0;
 }catch(DWORD rc){std::cout<<"wfp_error_"<<rc<<std::endl;return 1;}catch(...){std::cout<<"wfp_error_internal"<<std::endl;return 1;}}
