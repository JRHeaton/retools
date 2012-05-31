/*
 csigstrip - strip code signature from mach-o binaries
 
 John Heaton
 jheaton.dev@gmail.com
 http://github.com/Gojohnnyboi
 
 THIS IS FREE SOFTWARE. I will not guarantee that it will work correctly always,
 but go easy on me, I threw it together in an evening.
 As always, contributions are welcome :)
 
 What it does:
 If the binary has the LC_CODE_SIGNATURE load command, it
    - sets ncmds in the mach_header to ncmds - 1
    - sets sizeofcmds in the mach_header to sizeofcmds - 0x10 (the size of code sig cmd)
    - zeros out the code signature section
 
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/stat.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>

#define _errp(msg...) { \
    fprintf(stderr, "[ERROR] %s:%d:%s() " msg, __FILE__, __LINE__, __FUNCTION__); \
}
 // because i suck
#define _errpa(fmt, ...) { \
    fprintf(stderr, "[ERROR] %s:%d:%s() " fmt, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
}
#define _a(exp) if(!(exp)) { \
    _errp("_a(" #exp ")\n"); \
    exit(1); \
}

#define ESWAP16(x) (((x) >> 0x08) | ((x) << 0x08))
#define ESWAP32(x) (((x) >> 0x18) | \
    (((x) >> 0x08) & 0x0000FF00) | \
    (((x) << 0x08) & 0x00FF0000) | \
    ((x) << 0x18))
#define ESWAP64(x) (((x) >> 0x38) | \
    (((x) >> 0x28) & 0x000000000000FF00) |\
    (((x) >> 0x18) & 0x0000000000FF0000) |\
    (((x) >> 0x08) & 0x00000000FF000000) |\
    (((x) << 0x08) & 0x000000FF00000000) |\
    (((x) << 0x18) & 0x0000FF0000000000) |\
    (((x) << 0x28) & 0x00FF000000000000) |\
    ((x) << 0x38))

#define p16(f, val) (!(f) ? (val) : (ESWAP16((val))))
#define p32(f, val) (!(f) ? (val) : (ESWAP32((val))))
#define p64(f, val) (!(f) ? (val) : (ESWAP64((val))))

#define SUPPORTED_TYPES 3
struct {
    cpu_type_t      type;
    const char      *name;
} cpu_types[SUPPORTED_TYPES] = {
    { CPU_TYPE_I386,    "i386"      },
    { CPU_TYPE_X86_64,  "x86_64"    },
    { CPU_TYPE_POWERPC, "ppc"       }
};

void usage(const char *prog) {
    printf("usage:\t %s -i <infile> -o <outfile> [OPTIONS]\n\n"
           "options:\n\t"
           "-a\t arch name(if fat binary)\n\t"
           "-x\t arch index(if fat binary)\n\n\t"
           "options 'x' and 'a' are mutually exclusive\n\t"
           "passing neither will strip all architectures\n\n", prog);
    exit(1);
}

int strip_macho_sig(unsigned char *buf) {
    int fat = 0, _64 = 0;
    struct mach_header *hdr;
    unsigned char *pos = buf;
    
    hdr = (struct mach_header *)pos;
    fat = hdr->magic == MH_CIGAM || hdr->magic == MH_CIGAM_64; // damn you ppc
    _64 = p32(fat, hdr->magic) & 0x00000001;
    int supported = 0;
    for(int i=0;i<SUPPORTED_TYPES;++i) {
        if(p32(fat, hdr->cputype) == cpu_types[i].type) {
            supported = 1;
            printf("stripping code sig from arch: %s\n", cpu_types[i].name);
            break;
        }
    }
    if(!supported) {
        _errpa("architecture(%u) not supported, but this IS open source :D\n", hdr->cputype);
        return 1;
    }
    
    pos += _64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    for(uint32_t i=0;i<(p32(fat, hdr->ncmds));++i) {
        struct load_command *cmd = (struct load_command *)pos;
        
        if(p32(fat, cmd->cmd) == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *lcmd = (struct linkedit_data_command *)pos;
           // printf("found code sig cmd: size=0x%x dataoff=0x%x datasize=0x%x\n",
              //     p32(fat, lcmd->cmdsize), p32(fat, lcmd->dataoff), p32(fat, lcmd->datasize));
            
            uint32_t decCmds = (p32(fat, hdr->ncmds) - 1);
            uint32_t decCmdsSize = (p32(fat, hdr->sizeofcmds) - p32(fat, cmd->cmdsize));
            hdr->ncmds = p32(fat, decCmds);//!fat ? decCmds : ESWAP32(decCmds);
            hdr->sizeofcmds = p32(fat, decCmdsSize);//!fat ? decCmdsSize : ESWAP32(decCmdsSize);
            
            memset(buf+p32(fat, lcmd->dataoff), '\0', p32(fat, lcmd->datasize));
            memset(cmd, '\0', p32(fat, cmd->cmdsize));
            
            return 0;
        }
        
        pos += p32(fat, cmd->cmdsize);
    }
    
    return 1;
}

// untested, but should work...
int strip_fat_sigs(unsigned char *buf, int index) {
    struct fat_header *hdr = (struct fat_header *)buf;
    if(index != -1) {
        struct fat_arch *arch = (struct fat_arch *)(buf + sizeof(struct fat_header) + (index * sizeof(struct fat_arch)));
        if(strip_macho_sig(buf+ESWAP32(arch->offset)) != 0)
            return 1;
        else
            return 0;
    }
    
    for(int i=0;i<ESWAP32(hdr->nfat_arch);++i) {
        struct fat_arch *arch = (struct fat_arch *)(buf + sizeof(struct fat_header) + (i * sizeof(struct fat_arch)));
        if(strip_macho_sig(buf+ESWAP32(arch->offset)) != 0)
            return 1;
    }
    
    return 0;
}

int get_arch_index(unsigned char *buf, const char *name) {
    struct fat_header *hdr = (struct fat_header *)buf;
    cpu_type_t type = CPU_TYPE_ANY;
    
    for(int i=0;i<SUPPORTED_TYPES;++i) {
        if(!strcmp(cpu_types[i].name, name)) {
            type = cpu_types[i].type;
            break;
        }
    }
    if(type == CPU_TYPE_ANY)
        goto fail;
    
    for(int i=0;i<ESWAP32(hdr->nfat_arch);++i) {
        struct fat_arch *arch = (struct fat_arch *)(buf + sizeof(struct fat_header) + (i * sizeof(struct fat_arch)));
        cpu_type_t cputype = ESWAP32(arch->cputype);
        if(cputype == type) {
            return i;
        }
    }
    
fail:
    return -2;
}

int main(int argc, const char **argv) {
    char c;
    const char *i_path = NULL, *o_path = NULL, *arch_name = NULL;
    int arch_index = -1;
    struct stat st;
    FILE *in = NULL, *out = NULL;
    unsigned char *buf;
    
    // ./csigstr -i xxxx -o yyyy
    if(argc < 5)
        usage(argv[0]);
    
    while((c = getopt(argc, (char * const *)argv, "i:o:a:x:")) != -1) {
        switch(c) {
            case 'i':
                i_path = optarg;
                break;
            case 'o':
                o_path = optarg;
                break;
            case 'a':
                arch_name = optarg;
                break;
            case 'x':
                arch_index = (unsigned)strtol(argv[optind-1], NULL, 10);
                break;
        }
    }
    
    _a(o_path && i_path);
    if(stat(o_path, &st) == 0) {
        fprintf(stderr, "output file already exists\n");
        return 1;
    }
    if(stat(i_path, &st) != 0) {
        fprintf(stderr, "input file doesn't exist\n");
        return 1;
    }
    _a((in = fopen(i_path, "r")) != NULL);

    buf = malloc(st.st_size);
    _a(fread(buf, st.st_size, 1, in) != 0);
    
    if(arch_index == -1 && arch_name)
        arch_index = get_arch_index(buf, arch_name);
    _a(arch_index != -2);
    
    uint32_t magic = *(uint32_t *)buf;
    if(magic == FAT_CIGAM) { // assuming we're all on modern computers here
        if(strip_fat_sigs(buf, arch_index) != 0) {
            _errp("couldn't strip signature from fat file\n");
            goto cleanup;
        }
    } else if(magic == MH_MAGIC ||
              magic == MH_CIGAM ||
              magic == MH_MAGIC_64 ||
              magic == MH_CIGAM_64) {
        if(strip_macho_sig(buf) != 0) {
            _errp("couldn't strip signature from mach-o file\n");
            goto cleanup;
        }
    } else {
        _errp("file not mach-o\n");
        goto cleanup;
    }
    
    _a((out = fopen(o_path, "w")) != NULL);
    _a(fwrite(buf, st.st_size, 1, out) != 0);
    chmod(o_path, 0755);
    
cleanup:
    free(buf);
    fclose(in);
    if(out)
        fclose(out);
    
    return 0;
}