#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

typedef unsigned char byte_t;

typedef struct {
    byte_t inst;
    byte_t dest[4];
} jmp_inst_t;

#define JMP_INTEL_INST 0xE9

int main(int argc, const char **argv) {
    jmp_inst_t jmp;
    uint64_t dest = 0, start = 0, off = 0;
    
    if(argc < 3) {
        fprintf(stderr, "usage: %s [start] [dest]\n", argv[0]);
        exit(1);
    }
    
    start = strtoull(argv[1], NULL, 0x10);
    dest = strtoull(argv[2], NULL, 0x10);
    off = (dest - (start + 5));
    
    jmp.inst = JMP_INTEL_INST;
    jmp.dest[0] = (off >> 0x0);
    jmp.dest[1] = (off >> 0x8);
    jmp.dest[2] = (off >> 0x10);
    jmp.dest[3] = (off >> 0x18);
    
    printf("0x%016llx: jmp 0x%016llx\n", start, dest);
    printf("hex: %02x %02x %02x %02x %02x\n", jmp.inst, jmp.dest[0], jmp.dest[1], jmp.dest[2], jmp.dest[3]);

    return 0;
}