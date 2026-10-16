// Independent native readback: real CascLib index captures/header parser, plus
// deliberately strict span/hash checks and bounded one-chunk Z/N decoding.
// NOT CascOpenStorage, NOT an Agent runtime test. No write or network path.
#include "CascIndexFiles.cpp"
#include <fstream>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <openssl/evp.h>
#include <zlib.h>
extern "C" int casclib_parse_span_header(unsigned char *,size_t);
using Bytes=std::vector<unsigned char>;
static void need(bool ok,const char *s){if(!ok)throw std::runtime_error(s);}
static Bytes load(const char *name){std::ifstream f(name,std::ios::binary);need(bool(f),"open");f.seekg(0,std::ios::end);auto size=f.tellg();need(size>=0 && size<=1048576,"size");f.seekg(0);Bytes b((size_t)size);f.read((char*)b.data(),b.size());need(bool(f)||b.empty(),"read");return b;}
static unsigned long long be(const unsigned char *p,unsigned n){unsigned long long v=0;while(n--)v=(v<<8)|*p++;return v;}
static unsigned le4(const unsigned char *p){return unsigned(p[0])|unsigned(p[1])<<8|unsigned(p[2])<<16|unsigned(p[3])<<24;}
static Bytes hex(const char *s){std::string h(s);need(h.size()==32,"key_width");Bytes b;for(size_t i=0;i<h.size();i+=2){auto nib=[](char c)->int{return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;};int a=nib(h[i]),v=nib(h[i+1]);need(a>=0&&v>=0,"key_hex");b.push_back((a<<4)|v);}return b;}
static Bytes md5(const unsigned char *p,size_t n){Bytes out(16);unsigned size=0;need(EVP_Digest(p,n,out.data(),&size,EVP_md5(),nullptr)==1&&size==16,"md5");return out;}
int main(int argc,char **argv){try{
 need(argc==5||argc==6,"args_index_data_ekey_ckey_optional_archive");unsigned expected_archive=argc==6?(unsigned)std::strtoul(argv[5],nullptr,10):0;need(expected_archive<1024,"archive_arg");auto idx=load(argv[1]),data=load(argv[2]);auto ek=hex(argv[3]),ck=hex(argv[4]);need(idx.size()>=40,"index_short");unsigned xorv=0;for(int i=0;i<9;i++)xorv^=ek[i];unsigned bucket=(xorv&15)^(xorv>>4);
 CASC_INDEX_HEADER h{};need(CaptureIndexHeader_V2(h,idx.data(),idx.size(),bucket)==ERROR_SUCCESS,"casclib_header");DWORD n=0;
 auto entry=CaptureGuardedBlock2(idx.data()+h.HeaderLength+h.HeaderPadding,idx.data()+idx.size(),h.EntryLength,&n);
 need(entry && h.EntryLength==18 && n==18,"casclib_single_entry");need(!memcmp(entry,ek.data(),9),"prefix");
 auto loc=be(entry+9,5);unsigned archive=(unsigned)(loc>>30);unsigned offset=(unsigned)(loc&0x3fffffff);unsigned span=le4(entry+14);
 need(archive==expected_archive && span>66 && offset<=data.size() && span<=data.size()-offset,"location_bounds");auto p=data.data()+offset;
 for(int i=0;i<16;i++)need(p[i]==ek[15-i],"span_full_ekey");need(le4(p+16)==span && p[20]==0 && p[21]==0,"span_size_flags");need(le4(p+22)==hashlittle(p,22,0x3d6be971),"span_hash_a");
 const unsigned table[16]={0x049396b8,0x72a82a9b,0xee626cca,0x9917754f,0x15de40b1,0xf5a8a9b6,0x421eac7e,0xa9d55c9a,0x317fd40c,0x04faf80d,0x3d6be971,0x52933cfd,0x27f64b7d,0xc6f5c11b,0xd5757e3a,0x6c388745};
 // Match Agent checksum verification: XOR-fold all 30 bytes at absolute low32
 // address alignment; compare to encoded(location+30). Independent of Python.
 unsigned char fold[4]={};for(unsigned i=0;i<30;i++)fold[(unsigned(loc)+i)&3]^=p[i];unsigned q=unsigned(loc)+30;need(le4(fold)==(table[q&15]^q),"span_checksum_b");
 need(casclib_parse_span_header(p,span)==1,"casclib_blte_span_header");auto blte=p+30;unsigned bs=span-30;
 need(bs>=37 && !memcmp(blte,"BLTE",4) && be(blte+4,4)==36 && blte[8]==15 && be(blte+9,3)==1,"blte_geometry");need(md5(blte,36)==ek,"encoded_full_identity");
 unsigned cs=(unsigned)be(blte+12,4),ds=(unsigned)be(blte+16,4);need(cs==bs-36 && cs>0 && ds>0 && ds<=1048576,"chunk_bounds");auto chunk=blte+36;auto chunk_hash=md5(chunk,cs);need(!memcmp(chunk_hash.data(),blte+20,16),"chunk_hash");Bytes decoded(ds);
 if(chunk[0]=='Z'){
  z_stream z{};z.next_in=const_cast<Bytef*>(chunk+1);z.avail_in=cs-1;z.next_out=decoded.data();z.avail_out=ds;
  need(inflateInit(&z)==Z_OK,"inflate_init");int r=inflate(&z,Z_FINISH);bool good=r==Z_STREAM_END&&z.total_in==cs-1&&z.total_out==ds;inflateEnd(&z);need(good,"inflate_bounds");
 }else{need(chunk[0]=='N'&&cs-1==ds,"chunk_mode");memcpy(decoded.data(),chunk+1,ds);}
 need(md5(decoded.data(),decoded.size())==ck,"decoded_ckey");
 std::cout<<"{\"accepted\":true,\"casclib_index_capture\":true,\"casclib_span_header_parse\":true,\"strict_span_checksums\":true,\"full_ekey_verified\":true,\"decoded_ckey_verified\":true,\"archive\":"<<archive<<",\"offset\":"<<offset<<",\"span_bytes\":"<<span<<",\"decoded_bytes\":"<<ds<<"}\n";return 0;
 }catch(const std::exception &e){std::cout<<"{\"accepted\":false,\"code\":\""<<e.what()<<"\"}\n";return 1;}}
