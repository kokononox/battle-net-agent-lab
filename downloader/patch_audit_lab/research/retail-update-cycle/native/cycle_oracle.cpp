// CascLib index captures plus independent reserved-header policy.
// Header-sequence-selected research store. No directory-max selection.
// Seed supplied by researcher; not a Windows name/Agent execution test.
#include "CascIndexFiles.cpp"
#include <fstream>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <array>
#include <string>
using B=std::vector<unsigned char>;
static void need(bool x,const char*s){if(!x)throw std::runtime_error(s);}
static B load(std::string n){std::ifstream f(n,std::ios::binary);need(bool(f),"open");f.seekg(0,std::ios::end);auto z=f.tellg();need(z>=0&&z<=65536,"size");f.seekg(0);B b((size_t)z);f.read((char*)b.data(),b.size());need(bool(f)||b.empty(),"read");return b;}
static unsigned le(const unsigned char*p){return unsigned(p[0])|unsigned(p[1])<<8|unsigned(p[2])<<16|unsigned(p[3])<<24;}
static unsigned bucket(const unsigned char*p){unsigned v=0;for(int j=0;j<9;j++)v^=p[j];return ((v>>4)^v)&15;}
static B hex(std::string s){need(s.size()==32,"seed_width");B b;for(int i=0;i<32;i+=2){auto nib=[](char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;};int a=nib(s[i]),d=nib(s[i+1]);need(a>=0&&d>=0,"seed_hex");b.push_back(a*16+d);}return b;}
int main(int argc,char**argv){try{
 need(argc==4,"args_root_seed_capacity");std::string root=argv[1];B seed=hex(argv[2]);need(std::string(argv[3])=="1024","capacity_research_policy");B data=load(root+"/data.000");need(data.size()>=668&&data.size()<=856,"data_size");
 B ctl=load(root+"/shmem");need(ctl.size()==16384,"control_size");
 std::array<unsigned,16> sequences;bool updated=false;for(unsigned i=0;i<16;i++){sequences[i]=le(ctl.data()+0x110+i*4);need(sequences[i]==1||(i==2&&sequences[i]==2),"control_sequence");if(i==2)updated=sequences[i]==2;}
 if(updated)need(data.size()==856,"published_data_size");
 const unsigned table[16]={0x049396b8,0x72a82a9b,0xee626cca,0x9917754f,0x15de40b1,0xf5a8a9b6,0x421eac7e,0xa9d55c9a,0x317fd40c,0x04faf80d,0x3d6be971,0x52933cfd,0x27f64b7d,0xc6f5c11b,0xd5757e3a,0x6c388745};
 std::array<B,16> keys;unsigned char seen[16]={};
 for(unsigned slot=0;slot<16;slot++){
  B k=seed;k[1]=0;k[2]=0;bool found=false;for(unsigned trial=0;trial<256;trial++){k[0]=trial;if(((bucket(k.data())+1)&15)==slot){found=true;break;}}need(found,"key_search");keys[slot]=k;
  auto p=data.data()+slot*30;for(unsigned j=0;j<16;j++)need(p[j]==k[15-j],"reserved_key");need(le(p+16)==30&&p[20]==1&&p[21]==0,"reserved_size_flags");need(le(p+22)==hashlittle(p,22,0x3d6be971),"reserved_hash_a");unsigned char folded[4]={};for(unsigned j=0;j<30;j++)folded[(slot*30+j)&3]^=p[j];unsigned q=slot*30+30;need(le(folded)==(table[q&15]^q),"reserved_checksum_b");
 }
 B target=hex("faedca88d0a0ab30dae5519239582d31"),source=hex("914fcad4f4fcf4abb0ba52b197bb066f");unsigned ordinary=0,total=0;bool source_seen=false,target_seen=false;
 for(unsigned which=0;which<16;which++){
  char name[32];snprintf(name,sizeof(name),"/%02x%08x.idx",which,sequences[which]);B idx=load(root+name);CASC_INDEX_HEADER h{};need(CaptureIndexHeader_V2(h,idx.data(),idx.size(),which)==ERROR_SUCCESS,"casclib_header");DWORD n=0;auto e=CaptureGuardedBlock2(idx.data()+h.HeaderLength+h.HeaderPadding,idx.data()+idx.size(),h.EntryLength,&n);
  need(e&&h.EntryLength==18&&n==18*(1+(which==bucket(source.data()))+(updated&&which==bucket(target.data())))&&idx.size()==40+n,"index_geometry");
  for(unsigned at=0;at<n;at+=18){auto r=e+at;if(at)need(memcmp(r-18,r,9)<0,"index_order");unsigned long long loc=0;for(unsigned j=9;j<14;j++)loc=(loc<<8)|r[j];unsigned span=le(r+14);bool matched=false;
   for(unsigned slot=0;slot<16;slot++)if(!memcmp(r,keys[slot].data(),9)){need(!seen[slot]&&slot==which&&((bucket(r)+1)&15)==which&&loc==slot*30&&span==30,"reserved_index_binding");seen[slot]=1;matched=true;break;}
   if(!matched){need(bucket(r)==which&&span==188,"ordinary_index_shape");if(!memcmp(r,source.data(),9)){need(!source_seen&&loc==480,"source_binding");source_seen=true;}else{need(updated&&!target_seen&&!memcmp(r,target.data(),9)&&loc==668,"target_binding");target_seen=true;}ordinary++;}total++;
  }
 }
 for(auto v:seen)need(v==1,"missing_reserved_entry");need(source_seen&&target_seen==updated&&ordinary==1+unsigned(updated)&&total==17+unsigned(updated),"total_entries");
 std::cout<<"{\"accepted\":true,\"casclib_index_files\":16,\"reserved_headers\":16,\"index_entries\":"<<total<<",\"strict_reserved_checksums\":true,\"target_visible\":"<<(updated?"true":"false")<<",\"target_bucket_sequence\":"<<sequences[2]<<",\"exact_header_sequence_used\":true,\"max_filename_selection_used\":false,\"unpublished_tail_bytes\":"<<(updated?0:data.size()-668)<<",\"windows_identity_proven\":false}\n";return 0;
 }catch(const std::exception&e){std::cout<<"{\"accepted\":false,\"code\":\""<<e.what()<<"\"}\n";return 1;}}
