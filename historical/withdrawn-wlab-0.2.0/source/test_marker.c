#include <assert.h>
#include <stdio.h>
#include "marker.h"
int main(void){
 const char *m="WLAB_DETACH_a0123456789";
 const char *s[]={
  "WLAB_DETACH_a0123456789\n",
  "WLAB_DETACH_a0123456789\r\n",
  "  WLAB_DETACH_a0123456789 \r\n",
  "banner\r\nWLAB_DETACH_a0123456789\r\nend\r\n",
  "", "WLAB_DETACH_a0123456789",
  ".echo WLAB_DETACH_a0123456789; qd\r\n",
  "0:000> .echo WLAB_DETACH_a0123456789\r\n",
  "prefixWLAB_DETACH_a0123456789\r\n",
  "WLAB_DETACH_a0123456789suffix\r\n",
  "WLAB_DETACH_DIFFERENT\r\n",
  "WLAB_DETACH_a012345678\r\n",
  "\r\n\tWLAB_DETACH_a0123456789\t\r\n",
  "\n\nWLAB_DETACH_a0123456789\n\n"
 };
 int expected[]={1,1,1,1,0,0,0,0,0,0,0,0,1,1};
 for(size_t i=0;i<sizeof(s)/sizeof(s[0]);i++)assert(marker_line(s[i],strlen(s[i]),m)==expected[i]);
 const char *full="banner\nWLAB_DETACH_a0123456789\r\n";
 size_t n=strlen(full);
 for(size_t i=0;i<n;i++)assert(!marker_line(full,i,m));
 assert(marker_line(full,n,m));
 puts("14 marker fixtures and every partial-prefix case passed");return 0;
}
