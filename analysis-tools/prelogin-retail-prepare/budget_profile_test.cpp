#include "budget_profile.h"
#include <cassert>
int main(){
 retail_budget::Limits l;
 assert(retail_budget::select("",false,l)&&l.total==1073741824ULL&&l.phase==67108864ULL);
 assert(retail_budget::select("approved-2g-512m-t9",false,l)&&l.total==2147483648ULL&&l.phase==536870912ULL);
 assert(!retail_budget::select("2gb",false,l));
 assert(retail_budget::select("approved-2g-512m-t9",true,l)&&l.total==1073741824ULL&&l.phase==67108864ULL);
 assert(536870912ULL>=l.phase);return 0;
}
