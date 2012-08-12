/*
 sexec - execute code at ANY location in a dylib's __text section
 
 sexec loads the dylib into its process and does some voodoo to get the right offset, calls it, done.
 
 John Heaton & Dan Zimmerman
 gojohnnyboi@me.com
 
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <dlfcn.h>
#include <string.h>
#include <sys/stat.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>

#define _bail(fmt...) { \
    fprintf(stderr, fmt); \
    exit(1); \
}

int main(int argc, const char **argv) {
    struct stat     st;
    void            *handle;
    void            (*_exec_point)();
    unsigned long   offset;
    
    if(argc < 3) {
        printf("usage: %s <dylib> <offset>\n", argv[0]);
    }
    
    if(stat(argv[1], &st) != 0)
        _bail("file not found: %s\n", argv[1]);
    
    offset = strtol(argv[2], NULL, 16);
    handle = dlopen(argv[1], RTLD_NOW);
    for(uint32_t i = 0; i < _dyld_image_count(); ++i) {
        if(!strcmp(argv[1], _dyld_get_image_name(i))) {
            const struct mach_header *hdr = _dyld_get_image_header(i);
            
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            unsigned char *data;
            uint64_t size;
            if(hdr->magic == 0xfeedface)
                data = (unsigned char *)getsectdatafromheader(hdr, "__TEXT", "__text", (uint32_t *)&size);
            else
                data = (unsigned char *)getsectdatafromheader_64((const struct mach_header_64 *)hdr, "__TEXT", "__text", &size);
                        
            _exec_point = (void (*)())data + slide + offset;
//            printf("_exec_point: %p\n", _exec_point);
            _exec_point();
        }
    }
    
    dlclose(handle);
}