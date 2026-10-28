#pragma once
#include <string>
namespace retail_budget {
struct Limits {unsigned long long total=1073741824ULL,phase=67108864ULL;};
inline bool select(const std::string& requested,bool fixture,Limits& out){
 out=Limits{};
 if(fixture||requested.empty())return true;
 if(requested!="approved-2g-512m-t9")return false;
 out.total=2147483648ULL;out.phase=536870912ULL;return true;
}
}
