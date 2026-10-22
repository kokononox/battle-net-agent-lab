#ifndef WLAB_CORE_H
#define WLAB_CORE_H
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static void json_string(FILE *f,const char *s){fputc('"',f);for(const unsigned char *p=(const unsigned char*)s;*p;p++){unsigned c=*p;if(c=='"'||c=='\\'){fputc('\\',f);fputc(c,f);}else if(c<32)fprintf(f,"\\u%04x",c);else fputc(c,f);}fputc('"',f);}
static uint32_t zip_crc(uint32_t crc,const unsigned char *p,size_t n){while(n--){crc^=*p++;for(int k=0;k<8;k++)crc=(crc>>1)^(0xedb88320u& (uint32_t)-(int)(crc&1));}return crc;}
static void le16(FILE *f,uint16_t x){fputc(x&255,f);fputc(x>>8,f);}
static void le32(FILE *f,uint32_t x){le16(f,(uint16_t)x);le16(f,(uint16_t)(x>>16));}
static int zip_name_ok(const char *s){size_t n=strlen(s);if(!n||n>128||strstr(s,".."))return 0;for(size_t j=0;j<n;j++)if(!((s[j]>='a'&&s[j]<='z')||(s[j]>='0'&&s[j]<='9')||s[j]=='_'||s[j]=='.'))return 0;return 1;}
typedef struct{const char *name;FILE *file;uint32_t size,crc,offset;} ZipItem;
/* Caller supplies opened allowlisted files. Stored ZIP, no ZIP64, no compression. */
static int zip_write(FILE *out,ZipItem *items,size_t n){
 if(n>64)return 0;unsigned char buf[32768];uint64_t total=0;
 for(size_t j=0;j<n;j++){ZipItem *it=&items[j];if(!zip_name_ok(it->name)||!it->file)return 0;
  if(fseek(it->file,0,SEEK_END))return 0;long size=ftell(it->file);if(size<0||size>128*1024*1024L)return 0;it->size=(uint32_t)size;total+=it->size+256;if(total>400*1024*1024u)return 0;
  rewind(it->file);uint32_t crc=~0u;size_t nr;while((nr=fread(buf,1,sizeof(buf),it->file)))crc=zip_crc(crc,buf,nr);if(ferror(it->file))return 0;it->crc=~crc;rewind(it->file);
 }
 for(size_t j=0;j<n;j++){ZipItem *it=&items[j];long pos=ftell(out);if(pos<0)return 0;it->offset=(uint32_t)pos;uint16_t l=(uint16_t)strlen(it->name);
  le32(out,0x04034b50);le16(out,20);le16(out,0);le16(out,0);le16(out,0);le16(out,0x21);le32(out,it->crc);le32(out,it->size);le32(out,it->size);le16(out,l);le16(out,0);fwrite(it->name,1,l,out);
  uint32_t remain=it->size;while(remain){size_t want=remain>sizeof(buf)?sizeof(buf):remain,nr=fread(buf,1,want,it->file);if(nr!=want||fwrite(buf,1,nr,out)!=nr)return 0;remain-=(uint32_t)nr;}
 }
 long central=ftell(out);if(central<0)return 0;
 for(size_t j=0;j<n;j++){ZipItem *it=&items[j];uint16_t l=(uint16_t)strlen(it->name);le32(out,0x02014b50);le16(out,20);le16(out,20);le16(out,0);le16(out,0);le16(out,0);le16(out,0x21);le32(out,it->crc);le32(out,it->size);le32(out,it->size);le16(out,l);le16(out,0);le16(out,0);le16(out,0);le16(out,0);le32(out,0);le32(out,it->offset);fwrite(it->name,1,l,out);}
 long finish=ftell(out);if(finish<central)return 0;le32(out,0x06054b50);le16(out,0);le16(out,0);le16(out,(uint16_t)n);le16(out,(uint16_t)n);le32(out,(uint32_t)(finish-central));le32(out,(uint32_t)central);le16(out,0);
 return !ferror(out)&&fflush(out)==0;
}
static const char *stage_name(unsigned n){static const char *a[]={"unknown","launch","login","dashboard","in_world","map_change","idle"};return n<7?a[n]:a[0];}
#endif
