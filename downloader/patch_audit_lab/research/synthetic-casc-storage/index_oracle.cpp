// Calls the pinned CascLib private capture routines directly, not a reimplementation.
#include "CascIndexFiles.cpp"
#include <fstream>
#include <vector>
#include <iostream>
int main(int argc,char **argv) {
 if(argc!=3) return 2;
 std::ifstream f(argv[1],std::ios::binary);
 std::vector<unsigned char> data((std::istreambuf_iterator<char>(f)),{});
 if(data.size()<40 || data.size()>1048576) return 3;
 unsigned bucket=(unsigned)std::strtoul(argv[2],nullptr,10);
 CASC_INDEX_HEADER header{};
 DWORD result=CaptureIndexHeader_V2(header,data.data(),data.size(),bucket);
 if(result!=ERROR_SUCCESS) {std::cout<<"{\"accepted\":false,\"phase\":\"header\"}\n";return 4;}
 DWORD block_size=0;
 auto entries=CaptureGuardedBlock2(data.data()+header.HeaderLength+header.HeaderPadding,
                  data.data()+data.size(),header.EntryLength,&block_size);
 if(!entries || block_size%header.EntryLength) {std::cout<<"{\"accepted\":false,\"phase\":\"entries\"}\n";return 5;}
 std::cout<<"{\"accepted\":true,\"entry_length\":"<<header.EntryLength
          <<",\"entries\":"<<block_size/header.EntryLength<<",\"segment_bits\":"<<(unsigned)header.SegmentBits<<"}\n";
 return 0;
}
