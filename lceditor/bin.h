#ifndef __BIN_H
#define __BIN_H
#include <mach-o/loader.h>
#include <stdbool.h>

#define BYTE_MASK 7

#define round_byte(x) (((uintptr_t)(x) + BYTE_MASK) & ~((uintptr_t)BYTE_MASK))

#define round_page(x) (((uintptr_t)(x) + PAGE_MASK) & ~((uintptr_t)PAGE_MASK))

/* Constants for the cmd field of all load commands, the type */
#define	LC_SEGMENT_S		"Segment"	/* segment of this file to be mapped */
#define	LC_SYMTAB_S			"Symbol table"	/* link-edit stab symbol table info */
#define	LC_SYMSEG_S			"GDB symbol table"	/* link-edit gdb symbol table info (obsolete) */
#define	LC_THREAD_S			"Thread"	/* thread */
#define	LC_UNIXTHREAD_S		"Unix thread"	/* unix thread (includes a stack) */
#define	LC_LOADFVMLIB_S		"VM shared library"	/* load a specified fixed VM shared library */
#define	LC_IDFVMLIB_S		"VM shared library ID"	/* fixed VM shared library identification */
#define	LC_IDENT_S			"ID"	/* object identification info (obsolete) */
#define LC_FVMFILE_S		"VM file inclusion"	/* fixed VM file inclusion (internal use) */
#define LC_PREPAGE_S    	"Prepage"     /* prepage command (internal use) */
#define	LC_DYSYMTAB_S		"Dynamic link edit symbol table"	/* dynamic link-edit symbol table info */
#define	LC_LOAD_DYLIB_S		"Dylib" /* load a dynamically linked shared library */
#define	LC_ID_DYLIB_S		"Dylib ID"	/* dynamically linked shared lib ident */
#define LC_LOAD_DYLINKER_S	"Dynamic linker"	/* load a dynamic linker */
#define LC_ID_DYLINKER_S	"Dynamic linker ID"	/* dynamic linker identification */
#define	LC_PREBOUND_DYLIB_S "Prebound dylib"	/* modules prebound for a dynamically linked shared library */
#define	LC_ROUTINES_S		"Routines"	/* image routines */
#define	LC_SUB_FRAMEWORK_S 	"Sub-framework" /* sub framework */
#define	LC_SUB_UMBRELLA_S 	"Sub-umbrella"	/* sub umbrella */
#define	LC_SUB_CLIENT_S		"Sub-client" /* sub client */
#define	LC_SUB_LIBRARY_S  	"Sub-library"	/* sub library */
#define	LC_TWOLEVEL_HINTS_S "Namespace lookup hints" /* two-level namespace lookup hints */
#define	LC_PREBIND_CKSUM_S  "Checksum"	/* prebind checksum */

/*
 * load a dynamically linked shared library that is allowed to be missing
 * (all symbols are weak imported).
 */
#define	LC_LOAD_WEAK_DYLIB_S	"Weak dylib"

#define	LC_SEGMENT_64_S			"64-Segment" /* 64-bit segment of this file to be mapped */
#define	LC_ROUTINES_64_S		"64-Routines"	/* 64-bit image routines */
#define LC_UUID_S				"UUID"	/* the uuid */
#define LC_RPATH_S      		"Runpath"    /* runpath additions */
#define LC_CODE_SIGNATURE_S 	"Code-signature" /* local of code signature */
#define LC_SEGMENT_SPLIT_INFO_S "Split-segments" /* local of info to split segments */
#define LC_REEXPORT_DYLIB_S 	"Re-export dylib" /* load and re-export dylib */
#define	LC_LAZY_LOAD_DYLIB_S 	"Lazy load dylib" /* delay load of dylib until first use */
#define	LC_ENCRYPTION_INFO_S 	"Encryption" /* encrypted segment information */
#define	LC_DYLD_INFO_S 			"Dyld info" /* compressed dyld information */
#define	LC_DYLD_INFO_ONLY_S 	"Dyld info only"	/* compressed dyld information only */
#define	LC_LOAD_UPWARD_DYLIB_S 	"Upward dylib" /* load upward dylib */
#define LC_VERSION_MIN_MACOSX_S "Min macosx version" /* build for MacOSX min OS version */
#define LC_VERSION_MIN_IPHONEOS_S 	"Min iOS version" /* build for iPhoneOS min OS version */
#define LC_FUNCTION_STARTS_S 	"Function starts" /* compressed table of function start addresses */
#define LC_DYLD_ENVIRONMENT_S 	"Envirovar" /* string for dyld to treat like environment variable */
#define LC_MAIN_S 				"Main (thread)" /* replacement for LC_UNIXTHREAD */
#define LC_DATA_IN_CODE_S		"Data" /* table of non-instructions in __text */
#define LC_SOURCE_VERSION_S 	"Source version" /* source version used to build binary */
#define LC_DYLIB_CODE_SIGN_DRS_S	"Code-signing DR" /* Code signing DRs copied from linked dylibs */

struct bind_info {
    uint8_t segmentIndex;
    uint64_t segmentOffset;
    uint8_t type;
    int libraryOrdinal;
    int64_t addend;
    const char* symbolName;
    bool lazyPointer;
    bool weakImport;
};

struct bind_command {
    struct bind_info **binds;
    uint64_t nbinds;
};

struct reloc_info {
    uint64_t addr;
    uint64_t slide;
    uint8_t type;
    int segind;
};

struct reloc_command {
    struct reloc_info **relocations;
    uint64_t nrelocs;
};

struct load_commands {
    struct load_command **load_cmds;
    char **load_cmd_names;
    uint64_t ncmds;
};

struct seg_cmd {
    uint8_t bits;
    struct segment_command *cmd;
    struct section **sects;
    uint32_t nsects;
};

struct seg_commands {
    struct seg_cmd **seg_cmds;
    uint64_t nsegs;
};

struct library_commands {
    struct dylib_command **dylib_cmds;
    uint64_t ndylib;
};

typedef struct bin {
    int binfd;
	struct stat *binstat;
	uint8_t *binmem;
	struct symtab_command *symtab_cmd;
	struct dysymtab_command *dysymtab_cmd;
	struct segment_command *linkedit_segment;
    struct segment_command_64 *linkedit_segment_64;
	struct dyld_info_command *dyldinfo_cmd;
    struct reloc_command *reloc_cmd;
    struct load_commands *load_cmds;
    struct seg_commands *seg_cmds;
    struct bind_command *bind_cmd;
    struct bind_command *weak_bind_cmd;
    struct bind_command *lazy_bind_cmd;
    struct library_commands *lib_cmds;
	char isfat;
} bin_t;

typedef uint32_t pint_t;


void bin_close(bin_t *bin, uint32_t fattst);
void *bin_open(char *path, uint32_t *isfat,char writable);
void bin_load(bin_t *bin);
void bin_display(bin_t *bin, uint16_t verbosity);
void bin_find_gdgts(bin_t *bin);
char *bin_loadcmd_info(bin_t *bin, struct load_command *lc, uint16_t verbosity);
char bin_is_loaded(bin_t *bin);
char bin_is_sixfour(bin_t *bin);
void bin_add_load_command(bin_t *bin, struct load_command *lc, char *strtbl);
void bin_remove_load_command(bin_t *bin, uint32_t index);

#endif
