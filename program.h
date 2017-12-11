/* (c) 2017 Michael R. Tirado -- GPLv3+
 * GNU General Public License, version 3 or any later version.
 * contact: mtirado418@gmail.com
 */

#ifndef PROGRAM_H__
#define PROGRAM_H__

#include "eslib/eslib_fortify.h"
#define MAX_CAPLINE 4096

#ifndef PRG_CONFIGS_DIR
	#define PRG_CONFIGS_DIR "/etc/init/programs"
#endif
#ifndef PRG_CONFIG_SIZE /* should be able to completely fit in a pipe */
	#define PRG_CONFIG_SIZE 4096
#endif
#ifndef PRG_PATHLEN
	#define PRG_PATHLEN 255
#endif
#ifndef PRG_TTYLEN
	#define PRG_TTYLEN 7
#endif
#ifndef PRG_NAMELEN
	#define PRG_NAMELEN 31
#endif
#ifndef PRG_CMDLEN
	#define PRG_CMDLEN 1279
#endif
#ifndef PRG_ENVLEN
	#define PRG_ENVLEN 1279
#endif
#ifndef PRG_NUM_ENVIRON
	#define PRG_NUM_ENVIRON 63
#endif
#ifndef PRG_NUM_ARGUMENTS
	#define PRG_NUM_ARGUMENTS 63
#endif
#ifndef USERID_MAX
	#define USERID_MAX  65534
#endif
#ifndef GROUPID_MAX
	#define GROUPID_MAX 65534
#endif
#ifndef PRG_FILE_LIMIT
	#define PRG_FILE_LIMIT 1000
#endif
#ifndef PRG_RAPID_RESPAWN_USECS
	#define PRG_RAPID_RESPAWN_USECS (1000 * 300) /* 300 millisec */
#endif

struct program {
	/* avoid relative pointer to addr 0, considered as argv/environ sentinel */
	unsigned int unused_relative_addr_0;

	char environ_data[PRG_ENVLEN+1]; /* environ points here */
	char cmdline[PRG_CMDLEN+1]; /* binpath and argv point here */
	char name[PRG_NAMELEN+1];
	char ttynum[PRG_TTYLEN+1];
	char workdir[PRG_PATHLEN+1];
	unsigned char a_capabilities[NUM_OF_CAPS];
	unsigned char b_capabilities[NUM_OF_CAPS];
	unsigned char i_capabilities[NUM_OF_CAPS];
	pid_t pid; /* filled out by pid1 after forking */
	uid_t uid;
	gid_t gid;
	int respawn; /* -1 for unlimited respawns */
	struct timespec last_spawn;

	/* when file io process sends program to pid1, the pointers are relative
	 * from beginning of struct; they point to data in the above arrays */
	char *environ[PRG_NUM_ENVIRON+1]; /* + 1 for sentinel */
	char *argv[PRG_NUM_ARGUMENTS+1];
	char *binpath;

};

/* load all programs in configs dir */
int program_load_configs_dir(int pipeout);

/* convert in-flight relative pointers to absolute */
int program_land(struct program *prg);

#endif
