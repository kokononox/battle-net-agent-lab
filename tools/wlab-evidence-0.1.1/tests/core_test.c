#include "../source/core.h"
#include <assert.h>
int main(int argc,char **argv){
 char decoded[32];const unsigned char hello[]={0x68,0,0x69,0,0,0};assert(utf16le_z_to_utf8(hello,sizeof(hello),decoded,sizeof(decoded)));assert(!strcmp(decoded,"hi"));
 assert(argc==2); const char *dir=argv[1]; char path[2048];
 assert(zip_name_ok("net_events.jsonl"));assert(!zip_name_ok("../evil"));assert(!zip_name_ok("a/b"));assert(!zip_name_ok("a\\b"));assert(!zip_name_ok("A.txt"));assert(!zip_name_ok(""));assert(!zip_name_ok(".."));
 assert(!strcmp(stage_name(0),"unknown"));assert(!strcmp(stage_name(4),"in_world"));assert(!strcmp(stage_name(99),"unknown"));
 assert((~zip_crc(~0u,(const unsigned char*)"123456789",9))==0xcbf43926u);
 snprintf(path,sizeof(path),"%s/escaping.json",dir);FILE *json=fopen(path,"wb");assert(json);json_string(json,"سلام\n\t\r\001\"\\");assert(!fclose(json));
 FILE *a=tmpfile(),*b=tmpfile(),*c=tmpfile();assert(a&&b&&c);fwrite("hello\n",1,6,a);for(int i=0;i<100003;i++)fputc(i%256,c);
 ZipItem items[]={{.name="a.txt",.file=a},{.name="empty.txt",.file=b},{.name="binary.dat",.file=c}};
 snprintf(path,sizeof(path),"%s/bundle.zip",dir);FILE *out=fopen(path,"wb");assert(out);assert(zip_write(out,items,3));assert(!fclose(out));
 snprintf(path,sizeof(path),"%s/empty.zip",dir);out=fopen(path,"wb");assert(out);assert(zip_write(out,NULL,0));assert(!fclose(out));
 out=tmpfile();assert(out);ZipItem bad={.name="../unsafe.txt",.file=a};assert(!zip_write(out,&bad,1));assert(!zip_write(out,items,65));fclose(out);
 fclose(a);fclose(b);fclose(c);puts("portable C assertions passed");return 0;
}
