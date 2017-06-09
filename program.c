/* (c) 2017 Michael R. Tirado -- GPLv3+
 * GNU General Public License, version 3 or any later version.
 * contact: mtirado418@gmail.com
 *
 * TODO: currently if any program config has a syntax error the whole
 *       loader fails, this is annoying to deal with if unsure what
 *       is causing the error so there is a define PROGFAIL_NOPANIC
 *       that should be used here to recover from config syntax errors
 *       even though system startup was not successful.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include "program.h"

#define is_whitespace(ch) (ch == ' ' || ch == '\t')

/*
 * workdir	- working directory for execve
 * cmdline	- absolute path to binary with arguments
 * environ	- environ "EVAR1=value1 EVAR2=value2"
 * respawn	- number of respawns, -1 is unlimited
 * uid		- user id
 * gid		- group id
 * tty		- stdio, default is 0 (console). TODO negative could be for daemons
 *
 * TODO:
 * capable	- leave caps in bounding set "cap_net_bind_service cap_syslog etc"
 * wait		- block for milliseconds while checking for exit status to detect
 *		  failures, adding time to boot process.
 * after	- set launch ordering, error on circular dependency.
 * critical	- init failure if program fails to launch, failure option can be to
 * 		  prevent launching any more programs, shut down, or halt system
 */
enum {
	KW_WORKDIR=0,
	KW_CMDLINE,
	KW_ENVIRON,
	KW_RESPAWN,
	KW_UID,
	KW_GID,
	KW_TTY,
	KW_CAPABLE,
	KWCOUNT
};
#define KWLEN 8 /* + terminator */
const char cfg_keywords[KWCOUNT][KWLEN] = {
	"workdir",
	"cmdline",
	"environ",
	"respawn",
	"uid",
	"gid",
	"tty",
	"capable"
};

/* returns the address of the next non-whitespace and update index
 * the starting character is completely ignored.
 * return with errno=ECANCELED on null terminator/eof.
 */
static char *skip_whitespace(char *str, unsigned int *idx, const unsigned int max)
{
	unsigned int i = *idx;
	errno = 0;
	while (++i < max)
	{
		if (str[i] == '\0') {
			errno = ECANCELED;
			return NULL;
		}
		else if (!is_whitespace(str[i])) {
			*idx = i;
			return &str[i];
		}
	}
	errno = E2BIG;
	return NULL;
}

static char *program_relative_ptr(struct program *prg, char *ptr)
{
	return (char *)((size_t)ptr - (size_t)prg);
}
static char *program_absolute_ptr(struct program *prg, char *ptr)
{
	return (char *)((size_t)prg + (size_t)ptr);
}

/* convert in-flight relative poitners to absolute */
int program_land(struct program *prg)
{
	int i;
	char *rel_addr;
	char *abs_addr;
	size_t len;

	/* binpath */
	rel_addr = prg->binpath;
	abs_addr = (char *)prg + (size_t)rel_addr;
	len = strnlen(abs_addr, PRG_PATHLEN) + 1;
	if (prg->binpath + len >= (char *)sizeof(struct program)
			|| len >= PRG_PATHLEN)
		goto failure;
	prg->binpath = program_absolute_ptr(prg, prg->binpath);

	for (i = 0; i < PRG_NUM_ARGUMENTS; ++i)
	{
		if (prg->argv[i] == NULL)
			break;
		/* argv[] */
		rel_addr = prg->argv[i];
		abs_addr = (char *)prg + (size_t)rel_addr;
		len = strnlen(abs_addr, PRG_CMDLEN) + 1;
		if (prg->argv[i] + len >= (char *)sizeof(struct program)
				|| len >= PRG_CMDLEN)
			goto failure;
		prg->argv[i] = program_absolute_ptr(prg, prg->argv[i]);
	}

	for (i = 0; i < PRG_NUM_ENVIRON; ++i)
	{
		if (prg->environ[i] == NULL)
			break;
		/* environ[] */
		rel_addr = prg->environ[i];
		abs_addr = (char *)prg + (size_t)rel_addr;
		len = strnlen(abs_addr, PRG_ENVLEN) + 1;
		if (prg->environ[i] + len >= (char *)sizeof(struct program)
				|| len >= PRG_ENVLEN)
			goto failure;
		prg->environ[i] = program_absolute_ptr(prg, prg->environ[i]);
	}
	return 0;

failure:
	printf("program_land: corruption?\n");
	return -1;
}

static int load_environ(struct program *prg)
{
	char *env = prg->environ_data;
	char *start = NULL;
	unsigned int count = 0;
	unsigned int i = 0;
	unsigned int found_eq = 0;
	unsigned int search_eq = 0;

	/* find first var start */
	if (is_whitespace(env[0])) {
		start = skip_whitespace(env, &i, PRG_ENVLEN-1);
		if (start == NULL) {
			printf("no environment variables found\n");
			return -1;
		}
	}
	else {
		start = env;
	}
	if (*start == '=') {
		printf("unexpected = operator\n");
		return -1;
	}
	search_eq = 1; /* looking for = operator */
	for (; i < PRG_ENVLEN-1; ++i)
	{
		if (search_eq && env[i] == '=') {
			found_eq = 1;
			search_eq = 0;
		}
		else if (is_whitespace(env[i]) || env[i] == '\0') {
			/* end of environment string */
			if (found_eq == 0) {
				printf("missing = in environ \"VAR=val\"\n");
				return -1;
			}
			found_eq = 0;

			/* terminate and load into argv */
			env[i] = '\0';
			prg->environ[count] = program_relative_ptr(prg, start);
			start = NULL;
			if (++count > PRG_NUM_ENVIRON) {
				printf("max env vars: %d\n", PRG_NUM_ENVIRON);
				return -1;
			}

			/* find next var start */
			start = skip_whitespace(env, &i, PRG_ENVLEN-1);
			if (start == NULL) {
				if (errno == ECANCELED)
					break; /* eof */
				return -1;
			}
			else if (*start == '=') {
				printf("unexpected = operator\n");
				return -1;
			}
			if (i >= PRG_ENVLEN-1)
				break;
			search_eq = 1;
		}
	}
	if (env[PRG_ENVLEN-1] != '\0')
		return -1;
	if (search_eq) {
		printf("missing = operator\n");
		return -1;
	}
	if (count == 0) {
		printf("no environment variables found\n");
		return -1;
	}
	return 0;
}

/* setup binpath and argv */
static int load_cmdline(struct program *prg, char *params)
{
	char *cmdline = prg->cmdline;
	char *start = NULL;
	unsigned int i;
	unsigned int count = 0;

	strncpy(prg->cmdline, params, PRG_CMDLEN-1);
	prg->cmdline[PRG_CMDLEN-1] = '\0';
	/* terminate binpath */
	for (i = 0; i < PRG_CMDLEN-1; ++i)
	{
		if (cmdline[i] == '\0')
			break;
		if (is_whitespace(cmdline[i])) {
			cmdline[i] = '\0';
			break;
		}
	}
	if (i >= PRG_CMDLEN-1) {
		printf("cmdline bin path too long\n");
		return -1;
	}

	prg->binpath = program_relative_ptr(prg, prg->cmdline);
	prg->argv[count] = program_relative_ptr(prg, prg->name);
	count++;
	while (i < PRG_CMDLEN)
	{
		/* find start of argument */
		start = skip_whitespace(cmdline, &i, PRG_CMDLEN);
		if (start == NULL) {
			return 0;
		}
		/* find end of argument */
		while (i < PRG_CMDLEN)
		{
			if (is_whitespace(cmdline[i]) || cmdline[i] == '\0') {
				/* terminate and load into argv */
				cmdline[i] = '\0';
				prg->argv[count] = program_relative_ptr(prg, start);
				start = NULL;
				if (++count >= PRG_NUM_ARGUMENTS) {
					printf("max args: %d\n", PRG_NUM_ARGUMENTS);
					return -1;
				}
				break;
			}
			++i;
		}
	}
	return 0;

}

/* FIXME trailing whitespace causes error */
static long getlong(char *str, long *out)
{
	long ret;
	char *err = NULL;
	errno = 0;
	ret = strtol(str, &err, 10);
	if (err == NULL || *err || errno) {
		printf("bad long parameter\n");
		return -1;
	}
	*out = ret;
	return 0;
}

static int load_parameters(struct program *prg, int kw, char *params, const size_t len)
{
	long long_read;
	switch (kw)
	{
	case KW_WORKDIR:
		if (len >= PRG_PATHLEN) {
			printf("workdir max len: %d\n", PRG_PATHLEN-1);
			return -1;
		}
		if (*params != '/') {
			printf("workdir must be absolute path\n");
			return -1;
		}
		strncpy(prg->workdir, params, PRG_PATHLEN-1);
		prg->workdir[PRG_PATHLEN-1] = '\0';
		break;

	case KW_CMDLINE:
		if (len >= PRG_CMDLEN) {
			printf("cmdline max len: %d\n", PRG_CMDLEN-1);
			return -1;
		}
		if (*params != '/') {
			printf("cmdline bin path must be absolute path\n");
			return -1;
		}
		if (load_cmdline(prg, params)) {
			printf("load_cmdline failed\n");
			return -1;
		}
		break;

	case KW_ENVIRON:
		if (len >= PRG_ENVLEN) {
			printf("environ len: %d\n", PRG_ENVLEN);
			return -1;
		}
		strncpy(prg->environ_data, params, PRG_ENVLEN-1);
		prg->environ_data[PRG_ENVLEN-1] = '\0';
		if (load_environ(prg)) {
			printf("load_environ failed\n");
			return -1;
		}
		break;

	case KW_RESPAWN:
		if (getlong(params, &long_read))
			return -1;
		if (long_read < -1) {
			printf("bad respawn value, use -1 for infinite\n");
			return -1;
		}
		if (long_read >= LONG_MAX) {
			printf("bad respawn value, use -1 for infinite\n");
			return -1;
		}
		prg->respawn = long_read;
		break;

	case KW_UID:
		if (getlong(params, &long_read))
			return -1;
		if (long_read > USERID_MAX) {
			printf("uid too big\n");
			return -1;
		}
		else if (long_read < 0) {
			printf("uid is negative\n");
			return -1;
		}
		prg->uid = long_read;
		break;

	case KW_GID:
		if (getlong(params, &long_read))
			return -1;
		if (long_read > GROUPID_MAX) {
			printf("gid too big\n");
			return -1;
		}
		else if (long_read < 0) {
			printf("gid is negative\n");
			return -1;
		}
		prg->gid = long_read;
		break;

	case KW_TTY:
		if (getlong(params, &long_read))
			return -1;
		if (long_read >= LONG_MAX) {
			printf("uid too big\n");
			return -1;
		}
		else if (long_read < 0) {
			printf("TODO negative tty for logging daemons/etc \n");
			return -1;
		}
		else if (long_read == 0) {
			/* could silently use /dev/console instead of failing */
			printf("tty0 not supported\n");
			return -1;
		}
		if (snprintf(prg->ttynum, PRG_TTYLEN, "%li", long_read) >= PRG_TTYLEN) {
			printf("tty number truncated by PRG_TTYLEN=%d\n", PRG_TTYLEN);
			return -1;
		}
		break;

	case KW_CAPABLE:
		/* TODO */
		printf("TODO KW_CAPABLE\n");
		return -1;
		break;

	default:
		return -1;
	}
	return 0;
}

static int get_keyword(char *kw)
{
	unsigned int i = 0;

	for (; i < KWCOUNT; ++i)
	{
		if (strncmp(cfg_keywords[i], kw, KWLEN) == 0)
			return i;
	}
	return -1;
}

static int check_line(char *lnbuf, const size_t len)
{
	size_t i;
	for (i = 0; i < len; ++i)
	{
		if (lnbuf[i] < 32 || lnbuf[i] > 126) {
			if (lnbuf[i] != '\t' && lnbuf[i] != '\n') {
				printf("invalid character(%d)\n", lnbuf[i]);
				return -1;
			}
		}
	}
	return 0;
}

/* prepare keyword with parameters, return start of next line
 * len does not include newline */
static char *program_parse_line(struct program *prg, char *lnbuf, const size_t len)
{
	char *eol = lnbuf + len;
	char *kw_end;
	char *param_start;
	int kw;

	if (len == 0)
		return eol;

	/* error on strange characters */
	if (check_line(lnbuf, len))
		return NULL;

	/* find keyword end */
	for (kw_end = lnbuf; kw_end < eol; ++kw_end)
	{
		char c = *kw_end;
		if (is_whitespace(c)) {
			*kw_end = '\0'; /* insert terminator */
			break;
		}
	}
	if (kw_end >= eol) {
		printf("bad keyword, missing parameters?\n");
		return NULL;
	}
	kw = get_keyword(lnbuf);
	if (kw < 0) {
		printf("unknown keyword %s\n", lnbuf);
		return NULL;
	}

	/* find parameter start */
	for (param_start = kw_end+1; param_start < eol; ++param_start)
	{
		char c = *param_start;
		if (!is_whitespace(c)) {
			break; /* start here */
		}
	}
	if (param_start >= eol) {
		printf("cannot find parameters\n");
		return NULL;
	}

	*eol = '\0'; /* change newline to null terminator */
	if (load_parameters(prg, kw, param_start, eol - param_start))
		return NULL;
	return eol;
}

static int program_parse_config(struct program *prg, char *filename,
		char *fbuf, const size_t fsize)
{
	struct program newprg;
	const char *eof = fbuf + fsize;
	char *scan;
	unsigned int line_number = 1;

	if (fsize == 0) {
		printf("config file is empty\n");
		return -1;
	}

	memset(&newprg, 0, sizeof(struct program));
	strncpy(newprg.name, filename, PRG_NAMELEN-1);
	newprg.name[PRG_NAMELEN-1] = '\0';
	/* set defaults */
	newprg.respawn = 0;
	newprg.uid = USERID_MAX;
	newprg.gid = GROUPID_MAX;
	newprg.pid = 0;

	for (scan = fbuf; scan < eof; ++scan)
	{
		char *end = scan;
		char *start = scan;
		size_t len = 0;
		while (*end != '\n')
		{
			if (++len >= PRG_CONFIG_SIZE) {
				printf("config size exceeds %d\n", PRG_CONFIG_SIZE-1);
				return -1;
			}
			if (++end >= eof) {
				break;
			}
		}
		/* inserts null terminator after keyword */
		scan = program_parse_line(&newprg, start, len);
		if (scan == NULL) {
			printf("line number: %d\n", line_number);
			return -1;
		}
		++line_number;
	}
	if (newprg.workdir[0] != '/') {
		printf("workdir is missing\n");
		return -1;
	}
	if (newprg.binpath == NULL) {
		printf("cmdline is missing\n");
		return -1;
	}
	memcpy(prg, &newprg, sizeof(struct program));
	return 0;
}

/* load file completely into buf[size] */
static int file_read(int fd, char *buf, const unsigned int size)
{
	int r;
	unsigned int bytes_read = 0;
	while (bytes_read < size)
	{
		r = read(fd, &buf[bytes_read], size - bytes_read);
		if (r > 0) {
			bytes_read += r;
			if (bytes_read > size) {
				printf("file_read: file too big\n");
				return -1;
			}
			else if (bytes_read == size) {
				break;
			}
			else if (bytes_read < 1) {
				return -1;
			}
		}
		else if (r == 0) {
			break; /* EOF */
		}
		else if (r == -1) {
			if (errno == EINTR)
				continue;
			printf("file_read: %s\n", strerror(errno));
			return -1;
		}
		else {
			return -1;
		}
	}
	return bytes_read;
}

static int program_load_config(struct program *prg, char *filename)
{
	char cfg_path[PRG_PATHLEN];
	char fbuf[PRG_CONFIG_SIZE];
	struct stat st;
	size_t fsize;
	int fd;
	int r;

	memset(fbuf, 0, sizeof(fbuf));
	memset(prg, 0, sizeof(struct program));

	/* assemble path */
	r = snprintf(cfg_path, sizeof(cfg_path), "%s/%s", PRG_CONFIGS_DIR, filename);
	if (r >= (int)sizeof(cfg_path)) {
		printf("program config path too long: %s\n", filename);
		return -1;
	}

	/* load file into fbuf */
	fd = open(cfg_path, O_RDONLY);
	if (fd == -1) {
		printf("open(%s): %s\n", cfg_path, strerror(errno));
		return -1;
	}
	r = fstat(fd, &st);
	if (r == -1) {
		printf("fstat(%s): %s\n", cfg_path, strerror(errno));
		return -1;
	}
	if (!S_ISREG(st.st_mode)) {
		printf("expected regular file at %s\n", cfg_path);
		return -1;
	}
	r = file_read(fd, fbuf, sizeof(fbuf)-1);
	close(fd);
	if (r <= 0) {
		printf("problem reading program config: %s\n", cfg_path);
		return -1;
	}
	fsize = r;

	/* fill out program struct */
	if (program_parse_config(prg, filename, fbuf, fsize)) {
		printf("config(%s) parse error\n", cfg_path);
		return -1;
	}
	return 0;
}

/*  validate and return strlen
 *  0 skip file
 * -1 error
 */
static int check_filename(char *name)
{
	int len = strnlen(name, NAME_MAX);
	int i;
	if (len == 0 || len >= NAME_MAX) {
		return -1;
	}
	if (len >= PRG_NAMELEN - 1) {
		printf("program max namelen: %d\n", PRG_NAMELEN);
		return -1;
	}
	if (name[len] != '\0')
		return -1;

	/* ignore anything with a dot */
	for (i = 0; i < len; ++i)
	{
		if (name[i] == '.')
			return 0;
	}
	/* ignore backup files */
	if (name[len - 1] == '~') {
		return 0;
	}
	return len;
}

static int count_files(DIR *dir, unsigned int *out)
{
	const int limit = PRG_FILE_LIMIT;
	int count = 0;
	while (count <= limit)
	{
		struct dirent *dent;
		int r;
		dent = readdir(dir);
		if (!dent) {
			break;
		}
		r = check_filename(dent->d_name);
		if (r == 0)
			continue;
		else if (r < 0)
			return -1;
		++count;
	}
	if (count > limit) {
		printf("program limit: %d\n", limit);
		return -1;
	}
	*out = count;
	return 0;
}

static int file_write(int fd, char *buf, size_t size)
{
	size_t written = 0;
	while (written < size)
	{
		int r = write(fd, buf + written, size - written);
		if (r <= 0) {
			if (r == -1 && errno == EINTR) {
				continue;
			}
			printf("write: %s\n", strerror(errno));
			return -1;
		}
		written += r;
	}
	if (written != size) {
		printf("write pipe error\n");
		return -1;
	}
	return written;
}

int program_load_configs_dir(int pipeout)
{
	struct program prg;
	DIR *dir;
	int limit = PRG_FILE_LIMIT;
	unsigned int i;
	unsigned int count;

	dir = opendir(PRG_CONFIGS_DIR);
	if (!dir) {
		printf("opendir(%s): %s\n", PRG_CONFIGS_DIR, strerror(errno));
		return -1;
	}

	/* write count */
	if (count_files(dir, &count))
		goto failure;
	rewinddir(dir);
	if (file_write(pipeout, (char *)&count, sizeof(count)) != sizeof(count))
		goto failure;

	i = 0;
	while (i < count)
	{
		struct dirent *dent;
		int r;

		dent = readdir(dir);
		if (!dent) {
			printf("readdir: %s\n", strerror(errno));
			goto failure;
		}
		r = check_filename(dent->d_name);
		if (r == 0)
			continue;
		else if (r < 0)
			goto failure;
		else if (r >= PRG_NAMELEN) {
			printf("max config name length is %d\n", PRG_NAMELEN-1);
			goto failure;
		}

		if (program_load_config(&prg, dent->d_name)) {
			goto failure;
		}

		/* write program */
		if (file_write(pipeout, (char *)&prg, sizeof(prg)) != sizeof(prg)) {
			goto failure;
		}
		++i;
		if (--limit < 0) {
			printf("program limit is %d\n", PRG_FILE_LIMIT);
			goto failure;
		}
	}

	closedir(dir);
	return 0;
failure:
	closedir(dir);
	return -1;
}
