#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include "bin.h"

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>

#define STACKTRACE() \
	void* callstack[128]; \
int i, frames = backtrace(callstack, 128); \
char** strs = backtrace_symbols(callstack, frames); \
fprintf(stderr,"SHOWING STACK TRACE\n\n"); \
for (i = 0; i < frames; ++i) { \
	fprintf(stderr,"%s\n", strs[i]); \
} \
free(strs)

#ifndef _UINTPTR_T
#define _UINTPTR_T
typedef unsigned long   uintptr_t;
#endif /* _UINTPTR_T */

char bin_verify_mach_header(bin_t *bin, uint32_t *isfat);

void segcmd_fetch_sections(void *segcmd, char issixfour, void ***sections,uint32_t *nsects);
void bin_load_relocs(bin_t *bin);
void rebaseAt(bin_t *context, uintptr_t addr, uintptr_t slide, uint8_t type, int segind);

void bin_fetch_symtab_str(bin_t *bin, struct symtab_command* cmd, char **ret);
void bin_fetch_dyldinfo_str(bin_t *bin, struct dyld_info_command *cmd, char **ret);
char *bin_str_from_strtbl_at_index(bin_t *bin, uint32_t index);
void bin_fetch_dysymtab_str(bin_t *bin, struct dysymtab_command*cmd, char **ret);
char *_bin_fetch_binding_str(bin_t *bin, char *head, struct seg_commands *seg_cmds, struct bind_command *bind_cmd);
char *bin_libname_for_ordinal(bin_t *bin, int libraryOrdinal);

void _bin_fetch_module_for_sym_index(bin_t *bin, uint32_t index, struct dylib_module **ret);
void _bin_fetch_module_at_index(bin_t *bin, uint32_t index, struct dylib_module **ret);

void free_seg_commands(struct seg_commands *sc);
void free_load_commands(struct load_commands *lc);
void free_reloc_command(struct reloc_command* rc);
void free_bind_command(struct bind_command *bc);
void free_library_commands(struct library_commands *lc);

void bindDyldInfoAt(uint8_t segmentIndex, uint64_t segmentOffset, uint8_t type, int libraryOrdinal, int64_t addend, const char* symbolName, bool lazyPointer, bool weakImport, struct bind_command *bindcmd);
void bin_load_bindings(bin_t *bin, struct bind_command *bcmd, uint8_t *p, uint8_t *end, bool lazy);
void bin_load_libraries(bin_t *bin);

static uint64_t read_uleb128(uint8_t** pa, uint8_t* end) {
	uint8_t *p = *pa;
	uint64_t result = 0;
	int		 bit = 0;
	do {
		if (p == end) {
			fprintf(stderr,"Malformed uleb128 at %#llx\n",(uint64_t)p);
			return 0;
		}

		uint64_t slice = *p & 0x7f;

		if (bit > 63) {
			fprintf(stderr, "uleb128 too big for uint64, bit=%d, result=0x%0llX", bit, result);
			return 0;
		} else {
			result |= (slice << bit);
			bit += 7;
		}
	} while (*p++ & 0x80);
	*pa = p;
	return result;
}

static int64_t read_sleb128(uint8_t** pa, uint8_t* end) {
	uint8_t *p = *pa;
	int64_t result = 0;
	int bit = 0;
	uint8_t byte;
	do {
		if (p == end) {
			fprintf(stderr,"malformed sleb128");
			return 0;
		}
		byte = *p++;
		result |= (((int64_t)(byte & 0x7f)) << bit);
		bit += 7;
	} while (byte & 0x80);
	// sign extend negative numbers
	if ( (byte & 0x40) != 0 )
		result |= (-1LL) << bit;
	*pa = p;
	return result;
}

void *binmap(int fd, size_t binsize) {
	void *ret = malloc(binsize);
	bzero(ret,binsize);
	size_t hred = 0;
	while (hred < binsize) {
		hred += read(fd,ret+hred,1024);
	}
	return ret;
}

int binunmap(int fd, void *binmem, size_t binsize) {
	lseek(fd, 0x0, SEEK_SET);
	size_t hrit = 0;
	size_t leftover = binsize;
	while (leftover > 0) {
		size_t a = write(fd, binmem+hrit, leftover < 1024 ? leftover : 1024);
		if (a == -1) {
			break;
		}
		hrit += a;
		leftover -= a;
	}
	free(binmem);
	return 0;
}

void *binremap(void *binmem, size_t newsize, size_t oldsize) {
	uint8_t *tmp = (uint8_t *)malloc(newsize);
	memcpy(tmp,binmem,oldsize);
	free(binmem);
	return tmp;
}

void *bin_open(char *path, uint32_t *isfat, char writable) {
	struct stat *binstat = (struct stat*)malloc(sizeof(struct stat));
	if (stat(path,binstat) != 0) {
		perror("STAT");
		exit(6);
	}
	int binfd;
	if ((binfd = open(path,writable ? O_RDWR : O_RDONLY)) == -1) {
		perror("OPEN");
		exit(4);
	}
	void *binmem = NULL;
	if ((binmem = binmap(binfd, binstat->st_size)) == 0) {
		perror("MMAP");
		exit(5);
	}
	bin_t *ret = (bin_t *)malloc(sizeof(bin_t));
	bzero(ret,sizeof(bin_t));
	ret->binfd = binfd;
	ret->binstat = binstat;
	ret->binmem = binmem;
	bin_verify_mach_header(ret,isfat);
	if (*isfat) {
		free(ret);
		void **aret = (void **)calloc(sizeof(bin_t*),*isfat+1);//doubt youll have uint32max fat archs.....
		aret[0] = binmem;
		uint32_t i;
		for (i=0;i<*isfat;i++) {
			struct fat_arch *farch = (struct fat_arch*)(binmem+sizeof(struct fat_header)+sizeof(struct fat_arch)*i);
			void *arch = (void*)(binmem + OSSwapInt32(farch->offset));
			bin_t *abin = (bin_t *)malloc(sizeof(bin_t));
			bzero(abin,sizeof(bin_t));
			abin->binstat = binstat;
			abin->binmem = arch;
			abin->isfat = 0xFF;
			abin->binfd = binfd;
			bin_verify_mach_header(abin, NULL);
			aret[i+1] = (void*)abin;
		}
		return (void*)aret;
	} else {
		ret->isfat = 0x0;
	}
	return (void*)ret;
}

void bin_close(bin_t *bin,uint32_t nfat) {
	void *amem = NULL;
	struct stat *st = NULL;
	uint32_t i;
	int afd;
	if (nfat > 0) {
		amem = ((void**)bin)[0];
		st = ((bin_t*)(((void**)bin)[1]))->binstat;
		afd = ((bin_t*)(((void**)bin)[1]))->binfd;
	} else {
		amem = bin->binmem;
		st = bin->binstat;
		afd = bin->binfd;
	}
	if (binunmap(afd, amem, st->st_size) == -1) {
		perror("MUNMAP");
		exit(2);
	}
	close(afd);
	if (nfat > 0) {
		void **bins = (void**)bin;
		for (i=0;i<nfat;i++) {
			bin_t *abin = ((bin_t*)(bins[i+1]));
			if (!bin_is_loaded(abin)) {
				free(abin);
				continue;
			}
			free_reloc_command(abin->reloc_cmd);
			free_load_commands(abin->load_cmds);
			free_seg_commands(abin->seg_cmds);
			free_bind_command(abin->bind_cmd);
			free_bind_command(abin->weak_bind_cmd);
			free_bind_command(abin->lazy_bind_cmd);
			free_library_commands(abin->lib_cmds);
			free(abin);
		}
	} else {
		free_reloc_command(bin->reloc_cmd);
		free_load_commands(bin->load_cmds);
		free_seg_commands(bin->seg_cmds);
		free_bind_command(bin->bind_cmd);
		free_bind_command(bin->weak_bind_cmd);
		free_bind_command(bin->lazy_bind_cmd);
		free_library_commands(bin->lib_cmds);
	}
	free(st);
	free(bin);
}

void free_reloc_command(struct reloc_command* rc) {
	uint64_t i;
	for (i=0;i<rc->nrelocs;i++) {
		free(rc->relocations[i]);
	}
	free(rc->relocations);
	free(rc);
}

void free_bind_command(struct bind_command *bc) {
	uint64_t i;
	for (i=0;i<bc->nbinds;i++) {
		free(bc->binds[i]);
	}
	free(bc->binds);
	free(bc);
}

void free_load_commands(struct load_commands *lc) {
	free(lc->load_cmds);
	free(lc->load_cmd_names);
	free(lc);
}

void free_library_commands(struct library_commands *lc) {
	free(lc->dylib_cmds);
	free(lc);
}

void free_seg_commands(struct seg_commands *sc) {
	uint64_t i;
	for(i=0;i<sc->nsegs;i++) {
		free(sc->seg_cmds[i]->sects);
		free(sc->seg_cmds[i]);
	}
	free(sc->seg_cmds);
	free(sc);
}

void relocateData(uint8_t *dat, size_t size, uint64_t oset) {
	uint8_t *datcpy = (uint8_t*)malloc(size);
	memcpy(datcpy,dat,size);
	bzero(dat,size);
	memcpy(dat+oset,datcpy,size);
	free(datcpy);
}

void bin_relocate_load_commands(bin_t *bin, uint64_t fileoff, uint64_t size, uint64_t oset) {
	uint64_t end = fileoff + size;
	uint64_t i,j,k;
	for(i=0;i<bin->seg_cmds->nsegs;i++) {
		struct seg_cmd *sc = bin->seg_cmds->seg_cmds[i];
		if (sc->bits == 64) {
			struct segment_command_64 *segcmd = (struct segment_command_64*)(sc->cmd);
			if (segcmd->fileoff > fileoff) {
				segcmd->fileoff += oset;
				segcmd->vmaddr += oset;
			} else if (segcmd->filesize != 0 && segcmd->fileoff == 0) {
				segcmd->filesize += oset;
				segcmd->vmsize += oset;
			}
			for (j=0;j<sc->nsects;j++) {
				struct section_64 *sect = (struct section_64*)(sc->sects[j]);
				if ((sect->flags & SECTION_TYPE) == S_THREAD_LOCAL_VARIABLES) {
					uint64_t nstructs = sect->size / sizeof(struct tlv_descriptor);
					struct tlv_descriptor *tlvdesc = (struct tlv_descriptor*)(bin->binmem + sect->offset);
					for (k=0;k<nstructs;k++) {
						if (tlvdesc->offset > fileoff)
							tlvdesc->offset += oset;
					}
				}

				uint32_t section_type = sect->flags & SECTION_TYPE;
				if (section_type == S_LAZY_SYMBOL_POINTERS || section_type == S_LAZY_DYLIB_SYMBOL_POINTERS || section_type == S_THREAD_LOCAL_VARIABLE_POINTERS) {
					uint32_t stride = 0, l;
					uint64_t count = 0;
					if (bin_is_sixfour(bin))
						stride = 8;
					else
						stride = 4;

					count = sect->size / stride;

					for (l=0;l<count;l++) {
						if (stride == 8) {
							*(uint64_t*)(bin->binmem + sect->offset + stride * l) += oset;
						} else {
							*(uint32_t*)(bin->binmem + sect->offset + stride * l) += oset;
						}
					}
				} else if (strcmp(sect->sectname, "__program_vars") == 0) {
					uint32_t stride = 0, l;
					uint64_t count = 5;
					if (bin_is_sixfour(bin))
						stride = 8;
					else
						stride = 4;
					for (l = 1; l < count;l++) {
						if (stride == 8) {
							*(uint64_t*)(bin->binmem + sect->offset + stride * l) += oset;
						} else {
							*(uint32_t*)(bin->binmem + sect->offset + stride * l) += oset;
						}
					}
				}
				if (sect->offset > fileoff) {
					sect->offset += oset;
					sect->addr += oset;
				}
			}
		} else {
			struct segment_command *segcmd = (struct segment_command*)(sc->cmd);
			if (segcmd->fileoff > fileoff) {
				segcmd->fileoff += oset;
				segcmd->vmaddr += oset;
			} else if (segcmd->filesize != 0 && segcmd->fileoff == 0) {
				segcmd->filesize += oset;
				segcmd->vmsize += oset;
			}
			for (j=0;j<sc->nsects;j++) {
				struct section *sect = sc->sects[j];
				if ((sect->flags & SECTION_TYPE) == S_THREAD_LOCAL_VARIABLES) {
					uint64_t nstructs = sect->size / sizeof(struct tlv_descriptor);
					struct tlv_descriptor *tlvdesc = (struct tlv_descriptor*)(bin->binmem + sect->offset);
					for (k=0;k<nstructs;k++) {
						if (tlvdesc->offset > fileoff)
							tlvdesc->offset += oset;
					}
				}
				uint32_t section_type = sect->flags & SECTION_TYPE;
				if (section_type == S_LAZY_SYMBOL_POINTERS || section_type == S_LAZY_DYLIB_SYMBOL_POINTERS || section_type == S_THREAD_LOCAL_VARIABLE_POINTERS) {
					uint32_t stride = 0, l;
					uint64_t count = 0;
					if (bin_is_sixfour(bin))
						stride = 8;
					else
						stride = 4;

					count = sect->size / stride;

					for (l=0;l<count;l++) {
						if (stride == 8) {
							*(uint64_t*)(bin->binmem + sect->offset + stride * l) += oset;
						} else {
							*(uint32_t*)(bin->binmem + sect->offset + stride * l) += oset;
						}
					}
				} else if (strcmp(sect->sectname, "__program_vars") == 0) {
					uint32_t stride = 0, l;
					uint64_t count = 5;
					if (bin_is_sixfour(bin))
						stride = 8;
					else
						stride = 4;
					for (l = 1; l < count;l++) {
						if (stride == 8) {
							*(uint64_t*)(bin->binmem + sect->offset + stride * l) += oset;
						} else {
							*(uint32_t*)(bin->binmem + sect->offset + stride * l) += oset;
						}
					}
				}
				if (sect->offset > fileoff) {
					sect->offset += oset;
					sect->addr += oset;
				}
			}
		}
	}
	for(i=0;i<bin->load_cmds->ncmds;i++) {
		struct load_command *lc = bin->load_cmds->load_cmds[i];
		switch (lc->cmd) {
			case LC_ROUTINES:
				if (((struct routines_command*)lc)->init_address > fileoff)
					((struct routines_command*)lc)->init_address += oset;
				break;
			case LC_ROUTINES_64:
				if (((struct routines_command_64*)lc)->init_address > fileoff)
					((struct routines_command_64*)lc)->init_address += oset;
				break;
			case LC_SYMTAB:
				if (((struct symtab_command*)lc)->symoff > fileoff) {
					((struct symtab_command*)lc)->symoff += oset;
				}
				if (((struct symtab_command*)lc)->stroff > fileoff) {
					((struct symtab_command*)lc)->stroff += oset;
				}
				break;
			case LC_DYSYMTAB:
				if (((struct dysymtab_command*)lc)->tocoff > fileoff)
					((struct dysymtab_command*)lc)->tocoff += oset;
				if (((struct dysymtab_command*)lc)->modtaboff > fileoff)
					((struct dysymtab_command*)lc)->modtaboff += oset;
				if (((struct dysymtab_command*)lc)->extrefsymoff > fileoff)
					((struct dysymtab_command*)lc)->extrefsymoff += oset;
				if (((struct dysymtab_command*)lc)->indirectsymoff > fileoff)
					((struct dysymtab_command*)lc)->indirectsymoff += oset;
				if (((struct dysymtab_command*)lc)->extreloff > fileoff)
					((struct dysymtab_command*)lc)->extreloff += oset;
				if (((struct dysymtab_command*)lc)->locreloff > fileoff)
					((struct dysymtab_command*)lc)->locreloff += oset;			
				break;
			case LC_TWOLEVEL_HINTS:
				if (((struct twolevel_hints_command*)lc)->offset > fileoff)
					((struct twolevel_hints_command*)lc)->offset += oset;
				break;
			case LC_DATA_IN_CODE:
			{
				uint64_t nstructs = ((struct linkedit_data_command*)lc)->datasize / sizeof(struct data_in_code_entry);
				uint64_t l;
				struct data_in_code_entry *dice = (struct data_in_code_entry*)(bin->binmem + ((struct linkedit_data_command*)lc)->dataoff);
				for (l=0;l<nstructs;l++) {
					if (dice->offset > fileoff) {
						dice->offset += oset;
					}
					dice = (struct data_in_code_entry*)(dice + sizeof(struct data_in_code_entry));
				}
			} 
				if (((struct linkedit_data_command*)lc)->dataoff > fileoff)
					((struct linkedit_data_command*)lc)->dataoff += oset;
				break;
			case LC_CODE_SIGNATURE:
			case LC_SEGMENT_SPLIT_INFO:
			case LC_FUNCTION_STARTS:
			case LC_DYLIB_CODE_SIGN_DRS:
				if (((struct linkedit_data_command*)lc)->dataoff > fileoff)
					((struct linkedit_data_command*)lc)->dataoff += oset;
				break;
			case LC_ENCRYPTION_INFO:
				if (((struct encryption_info_command*)lc)->cryptoff > fileoff)
					((struct encryption_info_command*)lc)->cryptoff += oset;
				break;
			case LC_DYLD_INFO_ONLY:
			case LC_DYLD_INFO:
				if (((struct dyld_info_command*)lc)->rebase_off > fileoff)
					((struct dyld_info_command*)lc)->rebase_off += oset;
				if (((struct dyld_info_command*)lc)->bind_off > fileoff)
					((struct dyld_info_command*)lc)->bind_off += oset;
				if (((struct dyld_info_command*)lc)->weak_bind_off > fileoff)
					((struct dyld_info_command*)lc)->weak_bind_off += oset;
				if (((struct dyld_info_command*)lc)->lazy_bind_off > fileoff)
					((struct dyld_info_command*)lc)->lazy_bind_off += oset;
				if (((struct dyld_info_command*)lc)->export_off > fileoff)
					((struct dyld_info_command*)lc)->export_off += oset;
				break;
			case LC_SYMSEG:
				if (((struct symseg_command*)lc)->offset > fileoff)
					((struct symseg_command*)lc)->offset += oset;
				break;
			case LC_MAIN:
				if (((struct entry_point_command*)lc)->entryoff > fileoff)
					((struct entry_point_command*)lc)->entryoff += oset;
				break;
			default:
				// fprintf(stderr, "Unknown load_command %#x\n", lc->cmd);
				break;
		}
	}
}

void bin_add_load_command(bin_t *bin, struct load_command *lc, char *strtbl) {
	if (!bin_is_loaded(bin))
		bin_load(bin);

	size_t newsize = bin->binstat->st_size;
/*
	if (strtbl) {
		uint8_t *binstrtbl = bin->binmem + bin->symtab_cmd->stroff;
		uint64_t sizetoreloc = bin->binstat->st_size - (bin->symtab_cmd->stroff + bin->symtab_cmd->strsize);
		uint64_t relocoset = strlen(strtbl)+1;
		uint64_t aout;
		if ((aout = (relocoset & 4095)) != 0) {
			relocoset += (4096 - aout);
		}
		newsize += relocoset;
		bin->binmem = binremap(bin->binmem, newsize, bin->binstat->st_size);
		bin_load(bin);
		bin_relocate_load_commands(bin,binstrtbl-bin->binmem, sizetoreloc, relocoset);
		relocateData(binstrtbl, sizetoreloc, relocoset);
		memcpy(binstrtbl+bin->symtab_cmd->strsize, strtbl, strlen(strtbl)+1);
		// ((struct dylinker_command*)lc)->name.offset = 1;
		bin->symtab_cmd->strsize += strlen(strtbl)+1;
	}
*/
	struct mach_header *hdr = (struct mach_header*)bin->binmem;
	uint64_t endlc = (bin_is_sixfour(bin) ? sizeof(struct mach_header_64) : sizeof(struct mach_header)) + hdr->sizeofcmds;
	uint64_t texttextoset = bin_is_sixfour(bin) ? ((struct section_64*)((bin->seg_cmds->seg_cmds)[1]->sects)[0])->offset : ((struct section*)((bin->seg_cmds->seg_cmds)[1]->sects)[0])->offset;
	uint64_t relocoset = lc->cmdsize;

	bool relocateerthing = false;

	if (endlc + relocoset > texttextoset) {
		relocoset = round_page(relocoset);
		newsize += relocoset;
		if (bin->isfat) {
			fprintf(stderr,"Unable to add load command to fat file, not enough space between end of load commands and start of __TEXT,__text\n");
			exit(11);
		}
		bin->binmem = binremap(bin->binmem, newsize,bin->binstat->st_size);
		bin_load(bin);
		relocateerthing = true;
		// ^ might be a memory leak, will look into
	}

	hdr = (struct mach_header*)bin->binmem;
	hdr->ncmds += 1;
	hdr->sizeofcmds += lc->cmdsize;

	if (relocateerthing) {
		bin_relocate_load_commands(bin,endlc, bin->binstat->st_size - endlc, relocoset);
		relocateData(bin->binmem + endlc, bin->binstat->st_size - endlc, relocoset);
	}
	memcpy((char*)(bin->binmem+endlc),lc,lc->cmdsize);

	bin->binstat->st_size = newsize;
	bin->load_cmds->ncmds += 1;
	bin->load_cmds->load_cmds = (struct load_command**)reallocf(bin->load_cmds->load_cmds, sizeof(struct load_command*)*bin->load_cmds->ncmds);
	bin->load_cmds->load_cmds[bin->load_cmds->ncmds-1] = (struct load_command*)(bin->binmem + endlc);
	bin->load_cmds->load_cmd_names = (char **)reallocf(bin->load_cmds->load_cmd_names, sizeof(char*)*bin->load_cmds->ncmds);
	bin->load_cmds->load_cmd_names[bin->load_cmds->ncmds-1] = "Newly Added";
}

void bin_remove_load_command(bin_t *bin, uint32_t index) {
	if (!bin_is_loaded(bin))
		bin_load(bin);

	struct mach_header *hdr = (struct mach_header*)bin->binmem;
	if (hdr->ncmds == index + 1) {
		struct load_command *lc = (struct load_command *)(bin->binmem + (bin_is_sixfour(bin) ? sizeof(struct mach_header_64) : sizeof(struct mach_header)));
		uint32_t i;
		for(i=0;i<(hdr->ncmds - 1);i++) {
			lc = (struct load_command*)((uint8_t*)lc + lc->cmdsize);
		}
		hdr->sizeofcmds -= lc->cmdsize;
		hdr->ncmds -= 1;
	} else {
		struct load_command *lc = (struct load_command *)(bin->binmem + (bin_is_sixfour(bin) ? sizeof(struct mach_header_64) : sizeof(struct mach_header)));
		uint32_t i;
		uint64_t oset = 0;
		for(i=0;i<(hdr->ncmds);i++) {
			uint64_t acmdsize = 0;
			if (i == index) {
				oset = acmdsize = lc->cmdsize;
				bzero(lc,lc->cmdsize);
			} else if (oset != 0) {
				uint64_t j;
				acmdsize = lc->cmdsize;
				uint8_t *tmp = (uint8_t *)malloc(acmdsize);
				memcpy(tmp,lc,acmdsize);
				bzero(lc,acmdsize);
				memcpy((uint8_t*)((uint8_t*)lc - oset), tmp, acmdsize);
				free(tmp);
			} else {
				acmdsize = lc->cmdsize;
			}
			lc = (struct load_command*)((uint8_t*)lc + acmdsize);
		}
		hdr->sizeofcmds -= oset;
		hdr->ncmds -= 1;
	}
}

void bin_write(bin_t *bin, off_t offset, void *data, size_t len) {
	memcpy((void*)(bin->binmem + offset),data,len);
}

char bin_verify_mach_header(bin_t *bin, uint32_t *isfat) {
	if (isfat != NULL)
		*isfat = 0x0;
	uint32_t magik = *(uint32_t *)(bin->binmem);
	if (magik == MH_MAGIC_64 || magik == MH_MAGIC) {
		return magik == MH_MAGIC_64 ? 0xFF : 0x00;
	}
	if (magik == FAT_CIGAM) {
		struct fat_header *fhdr = (struct fat_header*)(bin->binmem);
		*isfat = OSSwapInt32(fhdr->nfat_arch);
		return 0x0;
	}
	if (isfat == NULL)
		return 0x0;
	puts("MAGIC: Unknown file type");
	exit(7);
}

#define SWITCHCASE(acmd,cmdnames,index) \
	case acmd:\
		cmdnames[index] = acmd ## _S; \
		break

void bin_load(bin_t *bin) {
	uint32_t magik = *(uint32_t*)bin->binmem;
	int padding = magik == MH_MAGIC_64 ? sizeof(uint32_t) : 0x0;
	struct mach_header *hdr = (struct mach_header*)bin->binmem;
	struct load_command **acmds = (struct load_command**)calloc(sizeof(struct load_command*),hdr->ncmds);
	char **acmdnames = (char**)calloc(sizeof(char*),hdr->ncmds);
	bin->load_cmds = (struct load_commands*)malloc(sizeof(struct load_commands));
	bzero(bin->load_cmds,sizeof(struct load_commands));
	bin->load_cmds->ncmds = hdr->ncmds;
	bin->seg_cmds = (struct seg_commands*)malloc(sizeof(struct seg_commands));
	bzero(bin->seg_cmds,sizeof(struct seg_commands));
	uint32_t cmd;
	off_t offset = sizeof(struct mach_header) + padding;
	unsigned q;
	for (cmd = 0; cmd < hdr->ncmds; cmd++) {
		struct load_command *lc = (struct load_command*)(bin->binmem + offset);
		switch (lc->cmd) {
			case LC_SYMTAB:
				acmdnames[cmd] = LC_SYMTAB_S;
				if (bin->symtab_cmd == NULL) {
					bin->symtab_cmd = (struct symtab_command*)lc;
				}
				break;
			SWITCHCASE(LC_SYMSEG,acmdnames,cmd);
			SWITCHCASE(LC_THREAD,acmdnames,cmd);
			SWITCHCASE(LC_UNIXTHREAD,acmdnames,cmd);
			SWITCHCASE(LC_LOADFVMLIB,acmdnames,cmd);
			SWITCHCASE(LC_IDFVMLIB,acmdnames,cmd);
			SWITCHCASE(LC_IDENT,acmdnames,cmd);
			SWITCHCASE(LC_FVMFILE,acmdnames,cmd);
			SWITCHCASE(LC_PREPAGE,acmdnames,cmd);
			case LC_DYSYMTAB:
				acmdnames[cmd] = LC_DYSYMTAB_S;
				if (bin->dysymtab_cmd == NULL) {
					bin->dysymtab_cmd = (struct dysymtab_command*)lc;
				}
				break;
			SWITCHCASE(LC_ID_DYLIB,acmdnames,cmd);
			SWITCHCASE(LC_LOAD_DYLINKER,acmdnames,cmd);
			SWITCHCASE(LC_ID_DYLINKER,acmdnames,cmd);
			SWITCHCASE(LC_PREBOUND_DYLIB,acmdnames,cmd);
			SWITCHCASE(LC_ROUTINES,acmdnames,cmd);
			SWITCHCASE(LC_SUB_FRAMEWORK,acmdnames,cmd);
			SWITCHCASE(LC_SUB_UMBRELLA,acmdnames,cmd);
			SWITCHCASE(LC_SUB_CLIENT,acmdnames,cmd);
			SWITCHCASE(LC_SUB_LIBRARY,acmdnames,cmd);
			SWITCHCASE(LC_TWOLEVEL_HINTS,acmdnames,cmd);
			SWITCHCASE(LC_PREBIND_CKSUM,acmdnames,cmd);
			SWITCHCASE(LC_LOAD_WEAK_DYLIB,acmdnames,cmd);
			SWITCHCASE(LC_LOAD_DYLIB,acmdnames,cmd);
			SWITCHCASE(LC_LOAD_UPWARD_DYLIB,acmdnames,cmd);
			SWITCHCASE(LC_REEXPORT_DYLIB,acmdnames,cmd);
			case LC_SEGMENT:
				acmdnames[cmd] = LC_SEGMENT_S;
				bin->seg_cmds->nsegs++;
				bin->seg_cmds->seg_cmds = (struct seg_cmd **)reallocf(bin->seg_cmds->seg_cmds, sizeof(struct seg_cmd*)*bin->seg_cmds->nsegs);
				bin->seg_cmds->seg_cmds[bin->seg_cmds->nsegs-1] = (struct seg_cmd*)malloc(sizeof(struct seg_cmd));
				bin->seg_cmds->seg_cmds[bin->seg_cmds->nsegs-1]->bits = 32;
				bin->seg_cmds->seg_cmds[bin->seg_cmds->nsegs-1]->cmd = (struct segment_command*)lc;
				segcmd_fetch_sections(bin->seg_cmds->seg_cmds[bin->seg_cmds->nsegs-1]->cmd,bin_is_sixfour(bin),(void***)&(bin->seg_cmds->seg_cmds[bin->seg_cmds->nsegs-1]->sects),&(bin->seg_cmds->seg_cmds[bin->seg_cmds->nsegs-1]->nsects));
				if (strcmp(((struct segment_command*)lc)->segname,SEG_LINKEDIT) == 0) {
					if (bin->linkedit_segment == NULL) {
						bin->linkedit_segment = ((struct segment_command*)lc);
					}
				}
				break;
			case LC_SEGMENT_64:
				acmdnames[cmd] = LC_SEGMENT_64_S;
				bin->seg_cmds->nsegs++;
				bin->seg_cmds->seg_cmds = (struct seg_cmd **)reallocf(bin->seg_cmds->seg_cmds, sizeof(struct seg_cmd*)*bin->seg_cmds->nsegs);
				bin->seg_cmds->seg_cmds[bin->seg_cmds->nsegs-1] = (struct seg_cmd*)malloc(sizeof(struct seg_cmd));
				bin->seg_cmds->seg_cmds[bin->seg_cmds->nsegs-1]->bits = 64;
				bin->seg_cmds->seg_cmds[bin->seg_cmds->nsegs-1]->cmd = (struct segment_command*)lc;
				segcmd_fetch_sections(bin->seg_cmds->seg_cmds[bin->seg_cmds->nsegs-1]->cmd,bin_is_sixfour(bin),(void***)&(bin->seg_cmds->seg_cmds[bin->seg_cmds->nsegs-1]->sects),&(bin->seg_cmds->seg_cmds[bin->seg_cmds->nsegs-1]->nsects));
				if (strcmp(((struct segment_command_64*)lc)->segname,SEG_LINKEDIT) == 0) {
					if (bin->linkedit_segment_64 == NULL) {
						bin->linkedit_segment_64 = ((struct segment_command_64*)lc);
					}
				}
				break;
			SWITCHCASE(LC_ROUTINES_64,acmdnames,cmd);
			SWITCHCASE(LC_UUID,acmdnames,cmd);
			SWITCHCASE(LC_RPATH,acmdnames,cmd);
			SWITCHCASE(LC_CODE_SIGNATURE,acmdnames,cmd);
			SWITCHCASE(LC_SEGMENT_SPLIT_INFO,acmdnames,cmd);
			SWITCHCASE(LC_LAZY_LOAD_DYLIB,acmdnames,cmd);
			SWITCHCASE(LC_ENCRYPTION_INFO,acmdnames,cmd);
			case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY:
				acmdnames[cmd] = lc->cmd & LC_REQ_DYLD ? LC_DYLD_INFO_ONLY_S : LC_DYLD_INFO_S;
				if (bin->dyldinfo_cmd == NULL) {
					bin->dyldinfo_cmd = (struct dyld_info_command *)lc;
				}
				break;
			SWITCHCASE(LC_VERSION_MIN_MACOSX,acmdnames,cmd);
			SWITCHCASE(LC_VERSION_MIN_IPHONEOS,acmdnames,cmd);
			SWITCHCASE(LC_FUNCTION_STARTS,acmdnames,cmd);
			SWITCHCASE(LC_DYLD_ENVIRONMENT,acmdnames,cmd);
			SWITCHCASE(LC_MAIN,acmdnames,cmd);
			SWITCHCASE(LC_DATA_IN_CODE,acmdnames,cmd);
			SWITCHCASE(LC_SOURCE_VERSION,acmdnames,cmd);
			SWITCHCASE(LC_DYLIB_CODE_SIGN_DRS,acmdnames,cmd);
			default:
				acmdnames[cmd] = "Unknown";
				break;
		};
		(acmds)[cmd] = (void*)lc;
		offset+=lc->cmdsize;
	}
	bin->load_cmds->load_cmds = acmds;
	bin->load_cmds->load_cmd_names = acmdnames;
	bin->lib_cmds = (struct library_commands *)malloc(sizeof(struct library_commands));
	bzero(bin->lib_cmds, sizeof(struct library_commands));
	bin_load_libraries(bin);
	bin_load_relocs(bin);
	struct dyld_info_command *lc = bin->dyldinfo_cmd;
	uint8_t *p = bin->binmem + lc->bind_off;
	uint8_t *end = p + lc->bind_size;
	struct bind_command *bc = (struct bind_command*)malloc(sizeof(struct bind_command));
	bzero(bc,sizeof(struct bind_command));
	bin->bind_cmd = bc;
	bin_load_bindings(bin,bc,p,end,false);
	p = bin->binmem + lc->weak_bind_off;
	end = p + lc->weak_bind_size;
	bc = (struct bind_command*)malloc(sizeof(struct bind_command));
	bzero(bc,sizeof(struct bind_command));
	bin->weak_bind_cmd = bc;
	bin_load_bindings(bin,bc,p,end,false);
	p = bin->binmem + lc->lazy_bind_off;
	end = p + lc->lazy_bind_size;
	bc = (struct bind_command*)malloc(sizeof(struct bind_command));
	bzero(bc,sizeof(struct bind_command));
	bin->lazy_bind_cmd = bc;
	bin_load_bindings(bin,bc,p,end,true);
}

void bin_load_libraries(bin_t *bin) {
	uint64_t i;
	for(i=0;i<bin->load_cmds->ncmds;i++) {
		struct load_command *lc = bin->load_cmds->load_cmds[i];
		switch (lc->cmd) {
			case LC_LOAD_DYLIB:
			case LC_LOAD_WEAK_DYLIB:
			case LC_REEXPORT_DYLIB:
			case LC_LOAD_UPWARD_DYLIB:
				bin->lib_cmds->ndylib++;
				bin->lib_cmds->dylib_cmds = (struct dylib_command**)reallocf(bin->lib_cmds->dylib_cmds,sizeof(struct dylib_command*) * bin->lib_cmds->ndylib);
				bin->lib_cmds->dylib_cmds[bin->lib_cmds->ndylib-1] = (struct dylib_command*)lc;
				break;
			default:
				break;
		}
	}
}

void rebaseAt(bin_t *context, uintptr_t addr, uintptr_t slide, uint8_t type, int segind) {
	context->reloc_cmd->nrelocs++;
	context->reloc_cmd->relocations = (struct reloc_info**)reallocf(context->reloc_cmd->relocations,sizeof(struct reloc_info*)*context->reloc_cmd->nrelocs);
	context->reloc_cmd->relocations[context->reloc_cmd->nrelocs-1] = (struct reloc_info*)malloc(sizeof(struct reloc_info));
	context->reloc_cmd->relocations[context->reloc_cmd->nrelocs-1]->addr = addr;
	context->reloc_cmd->relocations[context->reloc_cmd->nrelocs-1]->slide = slide;
	context->reloc_cmd->relocations[context->reloc_cmd->nrelocs-1]->type = type;
	context->reloc_cmd->relocations[context->reloc_cmd->nrelocs-1]->segind = segind;
}

void bin_load_relocs(bin_t *bin) {
	struct dyld_info_command *lc = bin->dyldinfo_cmd;
	bin->reloc_cmd = (struct reloc_command*)malloc(sizeof(struct reloc_command));
	bzero(bin->reloc_cmd, sizeof(struct reloc_command));
	uint64_t slide = 0;
	uint8_t *start = bin->binmem + lc->rebase_off;
	uint8_t* end = start + lc->rebase_size;
	uint8_t* p = start;
	uint8_t type = 0;
	int segmentIndex = 0;
	uint64_t address;
	uint64_t segmentEndAddress;
	if (bin_is_sixfour(bin)) {
		address = ((struct segment_command_64*)bin->seg_cmds->seg_cmds[0]->cmd)->vmaddr;
		segmentEndAddress = address + ((struct segment_command_64*)bin->seg_cmds->seg_cmds[0]->cmd)->vmsize;
	} else {
		address = ((struct segment_command*)bin->seg_cmds->seg_cmds[0]->cmd)->vmaddr;
		segmentEndAddress = address + ((struct segment_command*)bin->seg_cmds->seg_cmds[0]->cmd)->vmsize;
	}
	uint32_t count = 0;
	uint32_t skip = 0;
	bool done = false;
	bin_t *context = bin;
	uint32_t i;
	while ( !done && (p < end) ) {
		uint8_t immediate = *p & REBASE_IMMEDIATE_MASK;
		uint8_t opcode = *p & REBASE_OPCODE_MASK;
		++p;
		switch (opcode) {
			case REBASE_OPCODE_DONE:
				done = true;
				break;
			case REBASE_OPCODE_SET_TYPE_IMM:
				type = immediate;
				break;
			case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
				segmentIndex = immediate;
				if ( segmentIndex > bin->seg_cmds->nsegs ) {
					fprintf(stderr, "REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB has segment %d which is too large (%lld)\n", 
							segmentIndex, bin->seg_cmds->nsegs);
					return;
				}
				if (bin_is_sixfour(bin)) {
					address = ((struct segment_command_64*)bin->seg_cmds->seg_cmds[segmentIndex]->cmd)->vmaddr + read_uleb128(&p, end);
					segmentEndAddress = ((struct segment_command_64*)bin->seg_cmds->seg_cmds[segmentIndex]->cmd)->vmaddr + ((struct segment_command_64*)bin->seg_cmds->seg_cmds[segmentIndex]->cmd)->vmsize;
				} else {
					address = ((struct segment_command*)bin->seg_cmds->seg_cmds[segmentIndex]->cmd)->vmaddr + read_uleb128(&p, end);
					segmentEndAddress = ((struct segment_command*)bin->seg_cmds->seg_cmds[segmentIndex]->cmd)->vmaddr + ((struct segment_command*)bin->seg_cmds->seg_cmds[segmentIndex]->cmd)->vmsize;
				}
				break;
			case REBASE_OPCODE_ADD_ADDR_ULEB:
				address += read_uleb128(&p, end);
				break;
			case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
				address += immediate*sizeof(uintptr_t);
				break;
			case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
				for (i=0; i < immediate; ++i) {
					if ( address >= segmentEndAddress ) {
						fprintf(stderr, "Bad rebase address %#llx-%#llx at %i %#llx-%#llx : %#llx", (uint64_t)address, (uint64_t)segmentEndAddress, segmentIndex, (uint64_t)start, (uint64_t)end, (uint64_t)p);
						return;
					}
					rebaseAt(context, address, slide, type, segmentIndex);
					address += sizeof(uintptr_t);
				}
				break;
			case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
				count = read_uleb128(&p, end);
				for (i=0; i < count; ++i) {
					if ( address >= segmentEndAddress ) {
						fprintf(stderr, "Bad rebase address %#llx-%#llx at %i %#llx-%#llx : %#llx", (uint64_t)address, (uint64_t)segmentEndAddress, segmentIndex, (uint64_t)start, (uint64_t)end, (uint64_t)p);
						return;
					}
					rebaseAt(context, address, slide, type, segmentIndex);
					address += sizeof(uintptr_t);
				}
				break;
			case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
				if ( address >= segmentEndAddress ) {
					fprintf(stderr, "Bad rebase address %#llx-%#llx at %i %#llx-%#llx : %#llx", (uint64_t)address, (uint64_t)segmentEndAddress, segmentIndex, (uint64_t)start, (uint64_t)end, (uint64_t)p);
					return;
				}
				rebaseAt(context, address, slide, type, segmentIndex);
				address += read_uleb128(&p, end) + sizeof(uintptr_t);
				break;
			case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
				count = read_uleb128(&p, end);
				skip = read_uleb128(&p, end);
				for (i=0; i < count; ++i) {
					if ( address >= segmentEndAddress ) {
						fprintf(stderr, "Bad rebase address %#llx-%#llx at %i %#llx-%#llx : %#llx", (uint64_t)address, (uint64_t)segmentEndAddress, segmentIndex, (uint64_t)start, (uint64_t)end, (uint64_t)p);
						return;
					}
					rebaseAt(context, address, slide, type, segmentIndex);
					address += skip + sizeof(uintptr_t);
				}
				break;
			default:
				fprintf(stderr, "bad rebase opcode %#x\n", *p);
		}
	}
}

void bindDyldInfoAt(uint8_t segmentIndex, uint64_t segmentOffset, uint8_t type, int libraryOrdinal, int64_t addend, const char* symbolName, bool lazyPointer, bool weakImport, struct bind_command *bindcmd) {
	bindcmd->nbinds++;
	bindcmd->binds = (struct bind_info **)reallocf(bindcmd->binds, sizeof(struct bind_info*)*bindcmd->nbinds);
	struct bind_info *acmd = (struct bind_info *)malloc(sizeof(struct bind_info));
	acmd->segmentIndex = segmentIndex;
	acmd->segmentOffset = segmentOffset;
	acmd->type = type;
	acmd->libraryOrdinal = libraryOrdinal;
	acmd->addend = addend;
	acmd->symbolName = symbolName;
	acmd->lazyPointer = lazyPointer;
	acmd->weakImport = weakImport;
	bindcmd->binds[bindcmd->nbinds - 1] = acmd;
}

void bin_load_bindings(bin_t *bin, struct bind_command *bcmd, uint8_t *p, uint8_t *end, bool lazy) {
	uint32_t i;
	uint8_t type = 0;
	uint64_t segmentOffset = 0;
	uint8_t segmentIndex = 0;
	char* symbolName = NULL;
	int libraryOrdinal = 0;
	int64_t addend = 0;
	uint32_t count;
	uint32_t skip;
	uint64_t start = (uint64_t)p;
	bool weakImport = false;
	bool done = false;
	while ( !done && (p < end) ) {
		uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
		uint8_t opcode = *p & BIND_OPCODE_MASK;
		++p;
		switch (opcode) {
			case BIND_OPCODE_DONE:
				if (!lazy)
					done = true;
				break;
			case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
				libraryOrdinal = immediate;
				break;
			case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
				libraryOrdinal = read_uleb128(&p, end);
				break;
			case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
				// the special ordinals are negative numbers
				if ( immediate == 0 )
					libraryOrdinal = 0;
				else {
					int8_t signExtended = BIND_OPCODE_MASK | immediate;
					libraryOrdinal = signExtended;
				}
				break;
			case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
				weakImport = ( (immediate & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0 );
				symbolName = (char*)p;
				while (*p != '\0')
					++p;
				++p;
				break;
			case BIND_OPCODE_SET_TYPE_IMM:
				type = immediate;
				break;
			case BIND_OPCODE_SET_ADDEND_SLEB:
				addend = read_sleb128(&p, end);
				break;
			case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
				segmentIndex = immediate;
				segmentOffset = read_uleb128(&p, end);
				break;
			case BIND_OPCODE_ADD_ADDR_ULEB:
				segmentOffset += read_uleb128(&p, end);
				break;
			case BIND_OPCODE_DO_BIND:
				bindDyldInfoAt(segmentIndex, segmentOffset, type, libraryOrdinal, addend, symbolName, lazy, weakImport, bcmd);
				segmentOffset += sizeof(pint_t);
				break;
			case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
				bindDyldInfoAt(segmentIndex, segmentOffset, type, libraryOrdinal, addend, symbolName, lazy, weakImport, bcmd);
				segmentOffset += read_uleb128(&p, end) + sizeof(pint_t);
				break;
			case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
				bindDyldInfoAt(segmentIndex, segmentOffset, type, libraryOrdinal, addend, symbolName, lazy, weakImport, bcmd);
				segmentOffset += immediate*sizeof(pint_t) + sizeof(pint_t);
				break;
			case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
				count = read_uleb128(&p, end);
				skip = read_uleb128(&p, end);
				for (i=0; i < count; ++i) {
					bindDyldInfoAt(segmentIndex, segmentOffset, type, libraryOrdinal, addend, symbolName, lazy, weakImport, bcmd);
					segmentOffset += skip + sizeof(pint_t);
				}
				break;
			default:
				fprintf(stderr,"bad bind opcode %d", *p);
		}
	}	

}

char *bin_loadcmd_info(bin_t *bin, struct load_command *lc, uint16_t verbosity) {
	if (!bin_is_loaded(bin))
		return NULL;
	char *ret = NULL;
	switch (lc->cmd) {
		case LC_SEGMENT_64: {
			struct segment_command_64 *segcmd = (struct segment_command_64 *)lc;
			asprintf(&ret, "%s | %u sections", segcmd->segname, segcmd->nsects);
			break;
		}
		case LC_SEGMENT: {
			struct segment_command *segcmd = (struct segment_command*)lc;
			asprintf(&ret, "%s | %u sections", segcmd->segname, segcmd->nsects);
			break;
		}
		case LC_IDFVMLIB:
		case LC_LOADFVMLIB:
		case LC_ID_DYLIB:
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
		case LC_REEXPORT_DYLIB:
		case LC_SUB_FRAMEWORK:
		case LC_SUB_CLIENT:
		case LC_SUB_UMBRELLA:
		case LC_SUB_LIBRARY:
		case LC_ID_DYLINKER:
		case LC_LOAD_DYLINKER:
		case LC_RPATH:
		case LC_FVMFILE:
		case LC_DYLD_ENVIRONMENT: {
			struct dylinker_command *acmd = (struct dylinker_command*)lc;
			asprintf(&ret, "%s", (char*)lc+acmd->name.offset);
			break;
		}
		case LC_DYLD_INFO:
		case LC_DYLD_INFO_ONLY:
			if (verbosity > 2)
				bin_fetch_dyldinfo_str(bin, (struct dyld_info_command*)lc, &ret);
			break;
		case LC_MAIN:
			asprintf(&ret, "%#llx, stack size: %#llx", ((struct entry_point_command*)lc)->entryoff, ((struct entry_point_command*)lc)->stacksize);
			break;
		case LC_SOURCE_VERSION: {
			uint64_t avers = ((struct source_version_command*)lc)->version;
			asprintf(&ret, "%u.%u.%u.%u.%u", (uint32_t)(0xFFFFFF & (avers>>40)), (uint16_t)(0x3FF & (avers >> 30)),(uint16_t)(0x3FF & (avers >> 20)),(uint16_t)(0x3FF & (avers >> 10)),(uint16_t)(0x3FF & (avers >> 0)));
			break;
		}
		case LC_SYMTAB:
			if (verbosity > 1)
				bin_fetch_symtab_str(bin, (struct symtab_command*)lc, &ret);
			break;
		case LC_DYSYMTAB:
			if (verbosity > 1)
				bin_fetch_dysymtab_str(bin, (struct dysymtab_command*)lc,&ret);
			break;
		case LC_VERSION_MIN_MACOSX:
		case LC_VERSION_MIN_IPHONEOS: {
			uint32_t vers = ((struct version_min_command*)lc)->version;
			uint32_t sdk = ((struct version_min_command*)lc)->sdk;
			asprintf(&ret, "%u.%u.%u; sdk: %u.%u.%u", (uint16_t)(0xFFFF & (vers>>16)),(uint8_t)(0xFF & (vers>>8)),(uint8_t)(0xFF & (vers >> 0)),(uint16_t)(0xFFFF & (sdk>>16)),(uint8_t)(0xFF & (sdk>>8)),(uint8_t)(0xFF & (sdk >> 0)));
			break;
		}
		case LC_UUID: {
			uint8_t *uid = ((struct uuid_command*)lc)->uuid;
			asprintf(&ret,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",uid[0],uid[1],uid[2],uid[3],uid[4],uid[5],uid[6],uid[7],uid[8],uid[9],uid[10],uid[11],uid[12],uid[13],uid[14],uid[15]);
			break;
		}
		case LC_ROUTINES:
		case LC_ROUTINES_64:
		default:
			break;
	}

	return ret;
}

#undef SWITCHCASE

void _bin_fetch_module_at_index(bin_t *bin, uint32_t index, struct dylib_module **ret) {
	if (index >= bin->dysymtab_cmd->nmodtab)
		return;
	struct dylib_module *aret = NULL;
	char issixfour = bin_is_sixfour(bin);
	struct dylib_module *tabomod = (struct dylib_module*)(bin->binmem + bin->dysymtab_cmd->modtaboff);
	aret = (struct dylib_module*)((char *)tabomod + index * issixfour ? sizeof(struct dylib_module_64) : sizeof(struct dylib_module));
	*ret = aret;
}

void _bin_fetch_module_for_sym_index(bin_t *bin, uint32_t index, struct dylib_module **ret) {
	struct dylib_module *aret = NULL;
	uint32_t i;
	struct dylib_table_of_contents *tabocont = (struct dylib_table_of_contents*)(bin->binmem+bin->dysymtab_cmd->tocoff);
	for (i = 0; i < bin->dysymtab_cmd->ntoc; i++) {
		if (tabocont->symbol_index == index) {
			_bin_fetch_module_at_index(bin, tabocont->module_index, &aret);
			break;
		}
		tabocont += sizeof(struct dylib_table_of_contents);
	}
	*ret = aret;
}

void _bin_fetch_sym_at_index(bin_t *bin, uint32_t index, struct nlist **sym) {
	if (index >= bin->symtab_cmd->nsyms)
		return;
	struct nlist *nl = (struct nlist *)(bin->binmem+bin->symtab_cmd->symoff);
	char issixfour = bin_is_sixfour(bin);
	*sym = (struct nlist*)(nl+index * issixfour ? sizeof(struct nlist_64) : sizeof(struct nlist));
}


void bin_fetch_dysymtab_str(bin_t *bin, struct dysymtab_command*cmd, char **ret) {
	struct dylib_table_of_contents *tabocont = (struct dylib_table_of_contents*)(bin->binmem+cmd->tocoff);
	uint32_t i;
	char *aret = NULL;
	for (i=0;i<cmd->ntoc;i++) {
		struct nlist *sym;
		_bin_fetch_sym_at_index(bin, tabocont->symbol_index, &sym);
		char *symm = bin_str_from_strtbl_at_index(bin,sym->n_un.n_strx);
		struct dylib_module *mod = NULL;
		_bin_fetch_module_at_index(bin, tabocont->module_index, &mod);
		char *modd = bin_str_from_strtbl_at_index(bin,mod->module_name);
		size_t retlen = aret ? strlen(aret) : 0x0;
		aret = reallocf(aret, retlen+2+strlen(symm)+3+strlen(modd)+1);
		memcpy(aret+retlen, "\n\t",2);
		memcpy(aret+retlen+2, symm, strlen(symm));
		memcpy(aret+retlen+2+strlen(symm)," : ", 3);
		memcpy(aret+retlen+2+strlen(symm)+3,modd, strlen(modd)+1);
		tabocont += sizeof(struct dylib_table_of_contents);
	}
	
	*ret = aret;
}

char *bin_str_from_strtbl_at_index(bin_t *bin, uint32_t index) {
	return (char*)(bin->binmem+bin->symtab_cmd->stroff+index);
}

char bin_is_loaded(bin_t *bin) {
	if (bin->symtab_cmd == NULL || bin->dysymtab_cmd == NULL || (bin->linkedit_segment == NULL && bin->linkedit_segment_64 == NULL) || bin->dyldinfo_cmd == NULL || bin->reloc_cmd == NULL || bin->load_cmds == NULL || bin->seg_cmds == NULL)
		return 0x00;
	return 0xFF;
}

char bin_is_sixfour(bin_t *bin) {
	if (*(uint32_t*)bin->binmem == MH_MAGIC_64)
		return 0xFF;
	return 0x00;
}

void bin_fetch_symtab_str(bin_t *bin, struct symtab_command* cmd, char **ret) {
	if (!bin_is_loaded(bin))
		return;
	char *aret = NULL;
	char issixfour = bin_is_sixfour(bin);
	if (issixfour) {
		struct nlist_64 *nl = (struct nlist_64*)(bin->binmem+cmd->symoff);
		uint32_t i;
		for (i = 0; i < cmd->nsyms; i++) {
			size_t retlen = aret ? strlen(aret) : 0x0;
			char *token = NULL;
			if (i == bin->dysymtab_cmd->ilocalsym) {
				token = "\n\tlocal:";
			} else if (i == bin->dysymtab_cmd->iextdefsym) {
				token = "\n\texternal:";
			} else if (i == bin->dysymtab_cmd->iundefsym) {
				token = "\n\tundefined:";
			}
			if (token != NULL) {
				aret = reallocf(aret,retlen+strlen(token)+1);
				memcpy(aret+retlen,token,strlen(token)+1);
				retlen = strlen(aret);
			}
			char *symname = bin_str_from_strtbl_at_index(bin, nl->n_un.n_strx);
			char *tmp = NULL;
			asprintf(&tmp, "\n\t\t%s at %#llx",symname,nl->n_value);
			aret = reallocf(aret, retlen+strlen(tmp)+1);
			strcpy(aret+retlen,tmp);
			free(tmp);
			struct dylib_module *dmod = NULL;
			_bin_fetch_module_for_sym_index(bin, i, &dmod);
			if (dmod != NULL) {
				char *modname = bin_str_from_strtbl_at_index(bin, dmod->module_name);
				if (modname != NULL) {
					retlen = strlen(aret);
					aret = reallocf(aret, retlen+strlen(modname)+1+3);
					memcpy((void*)(aret+retlen)," : ",3);
					memcpy((void*)(3+aret+retlen),modname,strlen(modname)+1);
				}
			}
			nl = (struct nlist_64*)((char *)nl + sizeof(struct nlist_64));
		}
	} else {
		struct nlist *nl = (struct nlist*)(bin->binmem+cmd->symoff);
		uint32_t i;
		for (i = 0; i < cmd->nsyms; i++) {
			size_t retlen = aret ? strlen(aret) : 0x0;
			char *token = NULL;
			if (i == bin->dysymtab_cmd->ilocalsym) {
				token = "\n\tlocal:";
			} else if (i == bin->dysymtab_cmd->iextdefsym) {
				token = "\n\texternal:";
			} else if (i == bin->dysymtab_cmd->iundefsym) {
				token = "\n\tundefined:";
			}
			if (token != NULL) {
				aret = reallocf(aret,retlen+strlen(token)+1);
				memcpy(aret+retlen,token,strlen(token)+1);
				retlen = strlen(aret);
			}
			char *symname = bin_str_from_strtbl_at_index(bin, nl->n_un.n_strx);
			char *tmp = NULL;
			asprintf(&tmp,"\n\t\t%s at %#x",symname,nl->n_value);
			aret = reallocf(aret, retlen+strlen(tmp)+1);
			strcpy(aret+retlen,tmp);
			free(tmp);
			struct dylib_module *dmod = NULL;
			_bin_fetch_module_for_sym_index(bin, i, &dmod);
			if (dmod != NULL) {
				char *modname = bin_str_from_strtbl_at_index(bin, dmod->module_name);
				if (modname != NULL) {
					retlen = strlen(aret);
					aret = reallocf(aret, retlen+strlen(modname)+1+3);
					memcpy((void*)(aret+retlen)," : ",3);
					memcpy((void*)(3+aret+retlen),modname,strlen(modname)+1);
				}
			}
			nl = (struct nlist*)((char*)nl + sizeof(struct nlist));
		}
	}
	*ret = aret;
}

char *bin_symbol_for_addr(bin_t *bin, uint64_t addr) {
	if (bin_is_sixfour(bin)) {
		struct nlist_64 *nl = (struct nlist_64*)((char*)bin->binmem + bin->symtab_cmd->symoff);
		uint64_t i;
		for (i=0;i<bin->symtab_cmd->nsyms;i++) {
			if (nl->n_value == addr) {
				return bin_str_from_strtbl_at_index(bin,nl->n_un.n_strx);
			}
			nl+=sizeof(struct nlist_64);
		}
	}
	return "Unknown";
}

char *rebase_str_for_type(uint8_t type) {
	switch (type) {
		case REBASE_TYPE_POINTER:
			return "Pointer";
		case REBASE_TYPE_TEXT_ABSOLUTE32:
			return "Absolute32";
		case REBASE_TYPE_TEXT_PCREL32:
			return "PCRelative32";
		default:
			return "Unknown";
	}
}

void bin_fetch_dyldinfo_str(bin_t *bin, struct dyld_info_command *cmd, char **ret) {
	char *a = "\n\tRelocations:";
	char *aret = (char*)malloc(strlen(a)+1);
	strcpy(aret,a);
	uint64_t i;
	for(i=0;i<bin->reloc_cmd->nrelocs;i++) {
		char *tmp = NULL;
		asprintf(&tmp, "\n\t\t[%llu] Addr: %#llx type: %s segment: %s",i+1,bin->reloc_cmd->relocations[i]->addr,rebase_str_for_type(bin->reloc_cmd->relocations[i]->type), bin->seg_cmds->seg_cmds[bin->reloc_cmd->relocations[i]->segind]->cmd->segname);
		aret = (char*)reallocf(aret,strlen(aret)+strlen(tmp)+1);
		strcpy(aret+strlen(aret),tmp);
		free(tmp);
	}
	char *binds = _bin_fetch_binding_str(bin,"\n\tBindings:", bin->seg_cmds, bin->bind_cmd);
	aret = (char*)reallocf(aret,strlen(aret)+strlen(binds)+1);
	strcpy(aret+strlen(aret),binds);
	free(binds);
	char *lbinds = _bin_fetch_binding_str(bin,"\n\tLazy Bindings:", bin->seg_cmds, bin->lazy_bind_cmd);
	aret = (char*)reallocf(aret,strlen(aret)+strlen(lbinds)+1);
	strcpy(aret+strlen(aret),lbinds);
	free(lbinds);
	char *wbinds = _bin_fetch_binding_str(bin,"\n\tWeak Bindings:", bin->seg_cmds, bin->weak_bind_cmd);
	aret = (char*)reallocf(aret,strlen(aret)+strlen(wbinds)+1);
	strcpy(aret+strlen(aret),wbinds);
	free(wbinds);
	*ret = aret;
}

char *bin_libname_for_ordinal(bin_t *bin, int libraryOrdinal) {
	switch ( libraryOrdinal) {
		case BIND_SPECIAL_DYLIB_SELF:
			return "this-image";
		case BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
			return "main-executable";
		case BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
			return "flat-namespace";
	}
	if ( libraryOrdinal < BIND_SPECIAL_DYLIB_FLAT_LOOKUP )
		return "Unknown special ordinal";
	if (libraryOrdinal > bin->lib_cmds->ndylib)
		return "Ordinal out of range";
	return (char*)((uint8_t*)(bin->lib_cmds->dylib_cmds[libraryOrdinal-1]) + bin->lib_cmds->dylib_cmds[libraryOrdinal-1]->dylib.name.offset);
}

char *_bin_fetch_binding_str(bin_t *bin, char *head, struct seg_commands *seg_cmds, struct bind_command *bind_cmd) {
	char *aret = (char*)malloc(strlen(head)+1);
	strcpy(aret, head);
	uint64_t i;
	for(i=0;i<bind_cmd->nbinds;i++) {
		char *tmp = NULL;
		asprintf(&tmp, "\n\t\t[%llu] Segment: %s offset: %#llx type: %#x library: %s addend: %lli symbol: %s lazy: %s weak: %s",
				i,
				seg_cmds->seg_cmds[bind_cmd->binds[i]->segmentIndex]->cmd->segname,
				bind_cmd->binds[i]->segmentOffset,
				bind_cmd->binds[i]->type,
				bin_libname_for_ordinal(bin, bind_cmd->binds[i]->libraryOrdinal),
				bind_cmd->binds[i]->addend,
				bind_cmd->binds[i]->symbolName,
				bind_cmd->binds[i]->lazyPointer ? "true" : "false",
				bind_cmd->binds[i]->weakImport ? "true" : "false"
			);
		aret = (char*)reallocf(aret,strlen(aret)+strlen(tmp)+1);
		strcpy(aret+strlen(aret),tmp);
		free(tmp);
	}
	return aret;
}

void segcmd_fetch_sections(void *segcmd, char issixfour, void ***sections,uint32_t *nsects) {
	
	off_t offset = sizeof(struct segment_command) - 2*sizeof(uint32_t);
	if (issixfour) {
		offset += 2*sizeof(uint64_t);
	}
	*nsects = *(uint32_t*)(segcmd+offset);
	void **asections = (void **)calloc(sizeof(void*),*nsects);
	offset += 2*sizeof(uint32_t);
	uint32_t sect = 0;
	for (sect = 0; sect < *nsects; sect++) {
		struct section *asect = (struct section*)(segcmd+offset);
		asections[sect] = (void*)asect;
		offset += issixfour ? sizeof(struct section_64) : sizeof(struct section);
	}
	*sections = asections;
}

void bin_display(bin_t *bin, uint16_t verbosity) {
	if (!bin_is_loaded(bin))
		bin_load(bin);
	uint32_t i,segind=0;
	for (i=0;i<bin->load_cmds->ncmds;i++) {
		struct load_command *lc = bin->load_cmds->load_cmds[i];
		printf("[%u] %s",i,bin->load_cmds->load_cmd_names[i]);
		char *lcinf = NULL;
		if (verbosity && ((lcinf = bin_loadcmd_info(bin, lc, verbosity)) != NULL)) {
			printf(": %s",lcinf);
			free(lcinf);
		}
		putc('\n',stdout);
		if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64) {
			uint32_t j;
			for (j=0;j<bin->seg_cmds->seg_cmds[segind]->nsects;j++) {
				printf("\t[%u] %s\n",j+1,bin->seg_cmds->seg_cmds[segind]->sects[j]->sectname);
			}
			segind++;
		}
	}
}


void bin_find_gdgts_at(bin_t *bin, uint64_t filoff,uint64_t size, uint64_t vmaddr) {
	uint32_t nsyms = bin->symtab_cmd->nsyms;
	struct nlist *nlists = (struct nlist*)(bin->symtab_cmd->symoff + (char*)(bin->binmem));
	char sixfour = bin_is_sixfour(bin);
	uint8_t delta = sixfour ? sizeof(struct nlist_64) : sizeof(struct nlist);
	char retbyte[] = {0xc3};
	uint64_t i,j;
	for (i=0;i<size;i++) {
		char *cbyte = (char *)((char *)bin->binmem+filoff+i);
		if (strncmp(cbyte,retbyte,sizeof(retbyte)/sizeof(char)) == 0) {
			char *nm = NULL;
			struct nlist *clist = nlists;
			uint64_t adel = UINT_FAST64_MAX;
			for (j=0;j<nsyms;j++) {
				uint64_t a;
				if (sixfour) {
					a = ((struct nlist_64*)clist)->n_value;
				} else {
					a = 0x00000000000000000000000000000000 & clist->n_value;
				}
				if (clist->n_type & N_SECT) {
					uint64_t del = (i + vmaddr) - a;
					if ((i + vmaddr) > a && del < adel) {
						nm = bin_str_from_strtbl_at_index(bin,clist->n_un.n_strx);
						adel = del;
					}
				}
				clist = (struct nlist *)((char *)clist + delta);
			}
			printf("Found ");
			uint64_t k;
			for (k = i-13;k < i+2 ; k++) {
				unsigned char z = *(char*)((char*)bin->binmem +filoff+k);
				printf("%#x ", z & 0xff);
				if (z == 0xc3) {
					break;
				}
			}
			printf("at %#llx (%#llx) under %s\n",i,vmaddr+i,nm ? : "unknown");
		}
	}

}

void bin_find_gdgts(bin_t *bin) {
	if (!bin_is_loaded(bin))
		bin_load(bin);
	uint32_t i,segind,j;
	for (i=0;i<bin->load_cmds->ncmds;i++) {
		struct load_command *lc = bin->load_cmds->load_cmds[i];
		if (lc->cmd == LC_SEGMENT || lc->cmd == LC_SEGMENT_64) {
			for (j=0;j<bin->seg_cmds->seg_cmds[segind]->nsects;j++) {
				if (strcmp(bin->seg_cmds->seg_cmds[segind]->sects[j]->sectname,SECT_TEXT) == 0) {
					uint64_t sectsize,filoff,vmaddr;
					if (lc->cmd == LC_SEGMENT) {
						sectsize = 0x00000000000000000000000000000000 & bin->seg_cmds->seg_cmds[segind]->sects[j]->size;
						filoff = 0x00000000000000000000000000000000 & bin->seg_cmds->seg_cmds[segind]->sects[j]->offset;
						vmaddr = 0x00000000000000000000000000000000 & bin->seg_cmds->seg_cmds[segind]->sects[j]->addr;
					} else {
						sectsize = ((struct section_64*)(bin->seg_cmds->seg_cmds[segind]->sects[j]))->size;
						filoff = ((struct section_64*)(bin->seg_cmds->seg_cmds[segind]->sects[j]))->offset;
						vmaddr = ((struct section_64*)(bin->seg_cmds->seg_cmds[segind]->sects[j]))->addr;
					}
					printf("Found %s:%s at %#llx (%#llx) (vmaddr: %#llx)\n",((struct segment_command*)lc)->segname,bin->seg_cmds->seg_cmds[segind]->sects[j]->sectname,filoff,sectsize,vmaddr);
					bin_find_gdgts_at(bin, filoff,sectsize, vmaddr);
				}
			}
			segind++;
		}
	}
}
