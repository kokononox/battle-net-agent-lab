#include "../source/core.h"
int main(int argc,char **argv){
 if(argc!=3)return 3;size_t n=strlen(argv[1]);if(n%2||n>16384)return 3;
 unsigned char raw[8192];for(size_t i=0;i<n/2;i++){char b[3]={argv[1][2*i],argv[1][2*i+1],0};char *end;unsigned long v=strtoul(b,&end,16);if(*end||v>255)return 3;raw[i]=(unsigned char)v;}
 char out[24577];size_t cap=strtoul(argv[2],NULL,10);if(cap>sizeof(out))return 3;
 if(!utf16le_z_to_utf8(raw,n/2,out,cap))return 2;json_string(stdout,out);return 0;
}
