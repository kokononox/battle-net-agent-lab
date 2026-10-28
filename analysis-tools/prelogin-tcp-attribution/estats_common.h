#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tcpestats.h>
struct Stats { unsigned long long in=0,out=0,received=0,acked=0; };
ULONG enable(MIB_TCPROW& row){TCP_ESTATS_DATA_RW_v0 rw{};rw.EnableCollection=TRUE;return SetPerTcpConnectionEStats(&row,TcpConnectionEstatsData,(PUCHAR)&rw,0,sizeof(rw),0);}
ULONG read_stats(MIB_TCPROW& row,Stats& s){
 TCP_ESTATS_DATA_RW_v0 rw{};TCP_ESTATS_DATA_ROD_v0 rod{};
 ULONG e=GetPerTcpConnectionEStats(&row,TcpConnectionEstatsData,(PUCHAR)&rw,0,sizeof(rw),nullptr,0,0,(PUCHAR)&rod,0,sizeof(rod));
 if(e)return e;if(rw.EnableCollection!=TRUE)return ERROR_INVALID_STATE;
 s={rod.DataBytesIn,rod.DataBytesOut,rod.ThruBytesReceived,rod.ThruBytesAcked};return 0;
}
