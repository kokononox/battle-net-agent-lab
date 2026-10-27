#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <netioapi.h>
#include <iphlpapi.h>
#include <climits>
#include "network_diagnostics.h"
#pragma comment(lib,"iphlpapi.lib")
// Same aggregate and filtering as C10. Diagnostic capture does not change limits.
inline bool sample_network(unsigned long long& n,counter_diag::Sample* sample=nullptr){
 PMIB_IF_TABLE2 t=nullptr;if(GetIfTable2(&t)!=NO_ERROR)return false;
 n=0;bool any=false;if(sample)sample->interfaces.clear();
 for(ULONG i=0;i<t->NumEntries;i++){
  auto& r=t->Table[i];if(r.Type==IF_TYPE_SOFTWARE_LOOPBACK||r.OperStatus!=IfOperStatusUp)continue;
  any=true;if(ULLONG_MAX-n<r.InOctets||ULLONG_MAX-n-r.InOctets<r.OutOctets){FreeMibTable(t);return false;}
  n+=r.InOctets+r.OutOctets;
  if(sample)sample->interfaces[r.InterfaceLuid.Value]={r.InOctets,r.OutOctets};
 }
 FreeMibTable(t);
 if(sample){sample->total=n;sample->tick=GetTickCount64();}
 return any;
}
