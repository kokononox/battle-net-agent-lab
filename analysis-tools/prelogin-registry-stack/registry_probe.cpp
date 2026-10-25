#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static const wchar_t *path=L"Software\\BattleNetAgentLab\\RegistryProbe";
static const wchar_t value[]=L"abcdefab-abcd-4abc-abcd-abcdefabcdef";
__declspec(noinline) static int exercise(HKEY k) {
 BYTE b[256]={0};DWORD n=static_cast<DWORD>(sizeof(b)),t=0;
 if(RegSetValueExW(k,L"UserUUID",0,REG_SZ,reinterpret_cast<const BYTE*>(value),static_cast<DWORD>(sizeof(value)))!=ERROR_SUCCESS)return 3;
 if(RegQueryValueExW(k,L"UserUUID",nullptr,&t,b,&n)!=ERROR_SUCCESS)return 4;
 n=static_cast<DWORD>(sizeof(b));if(RegQueryValueExA(k,"UserUUID",nullptr,&t,b,&n)!=ERROR_SUCCESS)return 5;
 n=static_cast<DWORD>(sizeof(b));if(RegGetValueW(k,nullptr,L"UserUUID",RRF_RT_REG_SZ,&t,b,&n)!=ERROR_SUCCESS)return 6;
 n=static_cast<DWORD>(sizeof(b));if(RegQueryValueExW(k,L"Missing",nullptr,&t,b,&n)!=ERROR_FILE_NOT_FOUND)return 7;
 n=0;if(RegQueryValueExW(k,L"UserUUID",nullptr,&t,nullptr,&n)!=ERROR_SUCCESS)return 8;
 return 0;
}
int main() {
 HKEY k=nullptr;DWORD disposition=0;
 if(RegCreateKeyExW(HKEY_CURRENT_USER,path,0,nullptr,0,KEY_READ|KEY_WRITE,nullptr,&k,&disposition)!=ERROR_SUCCESS)return 2;
 int result=exercise(k);RegCloseKey(k);RegDeleteKeyW(HKEY_CURRENT_USER,path);return result;
}
