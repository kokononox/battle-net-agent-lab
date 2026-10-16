// Compile-time inclusion of pinned CascLib source; never execute Agent.exe.
#include "CascReadFile.cpp"
extern "C" int casclib_parse_span_header(unsigned char *data,size_t size) {
 CASC_FILE_SPAN span{};size_t header=0;
 DWORD code=ParseBlteHeader(&span,0,data,size,&header);
 return code==ERROR_SUCCESS && span.FrameCount==1 && header==42;
}
