#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "bin.h"

void usage(char *progname) {
	fprintf(stderr, "\n%s [binary] [-r | -a | -d | -g] [index|loadcommand] [fatindex]\n\n\t-d, --display : display info about `binary` (add v after `-d` to print more info); an optional index for fat binaries\n\t-r, --remove : remove a load command at `index` (load command index) and an optional fatindex (index of fat arch)\n\t-a, --add : add a load command with data `loadcommand` in arch at `fatindex` **partially implemented**\n\t-g, --gadget : find gadgets for ROP **doesnt work**\n\n",progname);
	exit(7);
}

void display(int argc, char *argv[]) {
	char *abin = argv[1];
	uint16_t verbosity = strlen(argv[2]) - 2;
	uint32_t isfat = 0x0;
	void *binret = bin_open(abin, &isfat,0);
	if (isfat) {
		void **bins = (void **)binret;
		uint32_t index = 0;
		if (argc >= 4) {
			index = strtoul(argv[3],NULL,10);
			bin_t *abin = ((bin_t*)(bins[index+1]));
			bin_display(abin, verbosity);
		} else {
			for (index=0;index<isfat;index++) {
				bin_t *abin = ((bin_t*)(bins[index+1]));
				bin_display(abin, verbosity);
			}
		}
		bin_close((bin_t*)bins,isfat);
	} else {
		bin_display((bin_t *)binret, verbosity);
		bin_close((bin_t*)binret,isfat);
	}
}

void gadget(int argc, char *argv[]) {
	exit(13);
	char *abin = argv[1];
	uint32_t isfat = 0x00000000;
	void *binret = bin_open(abin, &isfat,0);
	if (isfat) {
		void **bins = (void **)binret;
		uint32_t index = 0;
		for (index=0;index<isfat;index++) {
			bin_t *abin = ((bin_t*)(bins[index+1]));
			bin_find_gdgts((bin_t*)abin);
		}
		bin_close((bin_t*)bins,isfat);
	} else {
		bin_find_gdgts((bin_t *)binret);
		bin_close((bin_t*)binret,isfat);
	}
}

void add(int argc, char *argv[]) {
	if (argc < 5) {
		usage(argv[0]);
	}
	char *cmdname = argv[3];
	char *lcpayload = argv[4];
	struct load_command *lc = NULL;
	if (strcmp(cmdname, "LC_LOAD_DYLIB") == 0 || strcmp(cmdname, "LC_LOAD_WEAK_DYLIB") == 0 || strcmp(cmdname, "LC_REEXPORT_DYLIB") == 0) {
		uint64_t i;
		size_t payloadlen = strlen(lcpayload);
		uint32_t colonfound = 0;
		for(i=0;i<payloadlen;i++) {
			if (lcpayload[i] == ':') {
				colonfound++;
				lcpayload[i] = '\0';
			}
		}
		if (colonfound != 3) {
			fprintf(stderr,"Invalid dylib load command payload\n");
			exit(12);
		}
		size_t liblen = strlen(lcpayload);
		size_t s = sizeof(struct dylib_command) + liblen + 1;
		s = round_byte(s);
		struct dylib_command *dc = (struct dylib_command *)malloc(s);
		bzero(dc, s);

#define CHECKCMD(name, acmd, dylibcmd) \
		if (strcmp(name, #acmd ) == 0) \
			dylibcmd->cmd = acmd

		CHECKCMD(cmdname, LC_LOAD_DYLIB, dc);
		CHECKCMD(cmdname, LC_LOAD_WEAK_DYLIB, dc);
		CHECKCMD(cmdname, LC_REEXPORT_DYLIB, dc);

#undef CHECKCMD

		dc->cmdsize = s;
		dc->dylib.name.offset = sizeof(struct dylib_command);
		uint32_t tstamp = 0, cvers = 0, compvers = 0;
		char *chartstamp = lcpayload+liblen+1;
		tstamp = strtoul(chartstamp,NULL,10);
		char *charcvers = chartstamp + strlen(chartstamp) + 1;
		cvers = strtoul(charcvers,NULL,10);
		char *charchompvers = charcvers + strlen(charcvers) + 1;
		compvers = strtoul(charchompvers,NULL,10);
		dc->dylib.timestamp = tstamp;
		dc->dylib.current_version = cvers;
		dc->dylib.compatibility_version = compvers;
		memcpy((uint8_t*)dc + sizeof(struct dylib_command), lcpayload, strlen(lcpayload) + 1);
		// fprintf(stderr,"Created command:\nstruct dylib_command {\n\t%#x\n\t%#x\n\tstruct dylib {\n\t\t%s\n\t\t%#x\n\t\t%#x\n\t\t%#x\n\t}\n};\n",dc->cmd,dc->cmdsize,(char*)((uint8_t*)dc + sizeof(struct dylib_command)), dc->dylib.timestamp, dc->dylib.current_version, dc->dylib.compatibility_version);
		lc = (struct load_command *)dc;
	} else if (strcmp(cmdname, "LC_UUID") == 0) {
		struct uuid_command *uc = (struct uuid_command *)malloc(sizeof(struct uuid_command));
		uc->cmd = LC_UUID;
		uc->cmdsize = sizeof(struct uuid_command);
		memcpy(uc->uuid, lcpayload, 16);
		uint8_t *uid = uc->uuid;
		// fprintf(stderr,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",uid[0],uid[1],uid[2],uid[3],uid[4],uid[5],uid[6],uid[7],uid[8],uid[9],uid[10],uid[11],uid[12],uid[13],uid[14],uid[15]);
		lc = (struct load_command *)uc;
	} else if (strcmp(cmdname, "LC_DYLD_ENVIRONMENT") ==0) {
		size_t s = sizeof(struct dylinker_command) + strlen(lcpayload) + 1;
		s = round_byte(s);
		struct dylinker_command *dc = (struct dylinker_command*)malloc(s);
		bzero(dc,s);
		dc->cmd = LC_DYLD_ENVIRONMENT;
		dc->cmdsize = s;
		dc->name.offset = sizeof(struct dylinker_command);
		memcpy((uint8_t*)dc + sizeof(struct dylinker_command), lcpayload,strlen(lcpayload) + 1);
		lc = (struct load_command *)dc;
	} else if (strcmp(cmdname, "LC_SOURCE_VERSION") == 0) {
		struct source_version_command *svc = (struct source_version_command*)malloc(sizeof(struct source_version_command));
		svc->cmd = LC_SOURCE_VERSION;
		svc->cmdsize = sizeof(struct source_version_command);
		uint64_t i;
		size_t payloadlen = strlen(lcpayload);
		uint32_t periodfound = 0;
		for(i=0;i<payloadlen;i++) {
			if (lcpayload[i] == '.') {
				periodfound++;
				lcpayload[i] = '\0';
			}
		}
		char *majchar = lcpayload;
		char *majmidchar = lcpayload + strlen(lcpayload) + 1;
		char *midchar = majmidchar + strlen(majmidchar) + 1;
		char *midminchar = midchar + strlen(midchar) + 1;
		char *minchar = midminchar + strlen(midminchar) + 1;
		uint32_t maj = strtoul(majchar,NULL,10);
		uint32_t majmid = strtoul(majmidchar,NULL,10);
		uint32_t mid = strtoul(midchar,NULL,10);
		uint32_t midmin = strtoul(midminchar,NULL,10);
		uint32_t min = strtoul(minchar,NULL,10);
		if (maj > 16777215 || majmid > 1023 || mid > 1023 || midmin > 1023 || min > 1023) {
			fprintf(stderr,"Invalid version given\n");
		}
#define tenbit 1023
		svc->version = (uint64_t)(((uint64_t)(maj & 0x0000000000ffffff) << 40) | ((uint64_t)(majmid & tenbit) << 30) | ((uint64_t)(mid & tenbit) << 20) | ((uint64_t)(midmin & tenbit) << 10) | ((uint64_t)(min & tenbit) << 0));
#undef tenbit
		lc = (struct load_command*)svc;
	}

	if (!lc) {
		fprintf(stderr,"Failed to parse load command \"%s\"\n",cmdname);
	}

	char *abin = argv[1];
	uint32_t isfat = 0x00000000;
	void *binret = bin_open(abin, &isfat,1);
	if (isfat) {
		void **bins = (void **)binret;
		uint32_t index = 0;
		for (index=0;index<isfat;index++) {
			bin_t *abin = ((bin_t*)(bins[index+1]));
			bin_add_load_command(abin, lc, NULL);
		}
		bin_close((bin_t*)bins,isfat);
	} else {
		bin_add_load_command(binret, lc, NULL);
		bin_close((bin_t*)binret,isfat);
	}

}

void delete(int argc, char *argv[]) {
	if (argc < 4) {
		usage(argv[0]);
	}
	char *abin = argv[1];
	uint32_t index = strtoul(argv[3],NULL,10);
	uint32_t isfat = 0x00000000;
	void *binret = bin_open(abin, &isfat,0xff);
	if (isfat) {
		uint32_t aindex = 0;
		void **bins = (void **)binret;
		if (argc >= 5) {
			aindex = strtoul(argv[4],NULL,10);
			bin_t *abin = ((bin_t*)(bins[aindex+1]));
			bin_remove_load_command(abin,index);
		} else {
			usage(argv[0]);
		}
		bin_close((bin_t*)bins,isfat);
	} else {
		bin_remove_load_command((bin_t*)binret,index);
		bin_close((bin_t*)binret,isfat);
	}
}


int main(int argc, char *argv[]) {
	if (argc < 3)
		usage(argv[0]);
	switch (argv[2][1]) {
		case 'a':
			add(argc,argv);
			break;
		case 'r':
			delete(argc,argv);
			break;
		case 'd':
			display(argc,argv);
			break;
		case 'g':
			gadget(argc,argv);
			break;
		default:
			usage(argv[0]);
			break;
	}

	return 0;
}
