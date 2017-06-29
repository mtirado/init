/* (c) 2017 Michael R. Tirado -- GPLv3+
 * GNU General Public License, version 3 or any later version.
 * contact: mtirado418@gmail.com
 */

#ifndef PROGRAM_H__
#define PROGRAM_H__

#ifndef PRG_CONFIGS_DIR
	#define PRG_CONFIGS_DIR "/etc/init/programs"
#endif
#ifndef PRG_CONFIG_SIZE /* should be able to completely fit in a pipe */
	#define PRG_CONFIG_SIZE 4096
#endif
#ifndef PRG_PATHLEN
	#define PRG_PATHLEN 256
#endif
#ifndef PRG_TTYLEN
	#define PRG_TTYLEN 8
#endif
#ifndef PRG_NAMELEN
	#define PRG_NAMELEN 32
#endif
#ifndef PRG_CMDLEN
	#define PRG_CMDLEN 1280
#endif
#ifndef PRG_ENVLEN
	#define PRG_ENVLEN 1280
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

struct program {
	/* avoid relative pointer to addr 0, considered as argv/environ sentinel */
	unsigned int unused_relative_addr_0;

	char environ_data[PRG_ENVLEN]; /* environ points here */
	char cmdline[PRG_CMDLEN]; /* binpath and argv point here */
	char name[PRG_NAMELEN];
	char ttynum[PRG_TTYLEN];
	char workdir[PRG_PATHLEN];
	pid_t pid; /* filled out by pid1 after forking */
	uid_t uid;
	gid_t gid;
	int respawn; /* -1 for unlimited respawns */

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
