#ifndef WLAB_MARKER_H
#define WLAB_MARKER_H
#include <stddef.h>
#include <string.h>
/* Require a complete standalone line, not the echoed startup command. */
static int marker_line(const char *data, size_t len, const char *marker) {
    size_t start=0, n=strlen(marker);
    for(size_t i=0;i<len;i++) if(data[i]=='\n') {
        size_t a=start,b=i;
        while(a<b && (data[a]==' ' || data[a]=='\t' || data[a]=='\r')) a++;
        while(b>a && (data[b-1]==' ' || data[b-1]=='\t' || data[b-1]=='\r')) b--;
        if(b-a==n && memcmp(data+a,marker,n)==0) return 1;
        start=i+1;
    }
    return 0;
}
#endif
