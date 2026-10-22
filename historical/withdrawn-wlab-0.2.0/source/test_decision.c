#include <assert.h>
#include <stdio.h>
#include "decision.h"
int main(void){
 int successes=0;
 for(unsigned i=0;i<256;i++){
  int got=attach_passed(i&1,i&2,i&4,i&8,i&16,i&32,i&64,i&128);
  assert(!!got==(i==127));successes+=!!got;
 }
 assert(successes==1);
 assert(approved_hash(APPROVED_SHA));assert(!approved_hash(NULL));assert(!approved_hash(""));
 assert(!approved_hash("1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753b"));
 assert(!approved_hash("1C51E68C00E7183C2C187606D2C443C27252A629406454DE4AFEC336E8C5753A"));
 assert(!approved_hash(APPROVED_SHA "suffix"));
 puts("256 outcome combinations and 6 identity fixtures passed");return 0;
}
