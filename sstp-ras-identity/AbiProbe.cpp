#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <ras.h>
#include <ipifcons.h>
#include <cstdio>
#include <cstddef>
int main() {
 std::printf("{\"ras_size\":%zu,\"projection_size\":%zu,\"entry_name_offset\":%zu,\"entry_guid_offset\":%zu,\"logon_luid_offset\":%zu,\"correlation_offset\":%zu,\"all_users_mask\":%u,\"projection_kind\":%u,\"ppp_type\":%u}\n",
 sizeof(RASCONNW),sizeof(RASPPPIPW),offsetof(RASCONNW,szEntryName),offsetof(RASCONNW,guidEntry),offsetof(RASCONNW,luid),offsetof(RASCONNW,guidCorrelationId),
 static_cast<unsigned>(RASCF_AllUsers),static_cast<unsigned>(RASP_PppIp),static_cast<unsigned>(IF_TYPE_PPP));
 return 0;
}
