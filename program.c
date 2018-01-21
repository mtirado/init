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
#include <linux/capability.h>

#include "program.h"
#include "eslib/eslib.h"

/*
 * workdir	 - working directory for execve
 * cmdline	 - absolute path to binary with arguments
 * environ	 - environ EVAR1=value1 EVAR2=value2
 * respawn	 - number of respawns, -1 is unlimited
 * uid		 - user id
 * gid		 - group id
 * tty		 - stdio, unspecified default is /dev/null
 * capable <set> - leave caps in bounding set "CAP_NET_BIND_SERVICE CAP_SYSLOG etc"
 * wait <millisecs> <wait_file>
 *               - sleep for some number of milliseconds before next program spawn.
 *                 if a file path is also supplied, unlink file before exec, and
 *                 cancel sleep when that file reappears. this is only done once
 *                 during system init, not for respawns.
 * faultless     - if program file has been loaded, don't exec unless faultless
 *                 e.g: if the wait_file timed out on the program we were after
 * rlimit        - set resource hard limit, setrlimit(2)
 *
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
	KW_AFTER,
	KW_WAIT,
	KW_FAULTLESS,
	KW_RLIMIT,
	KWCOUNT
};
#define KWSIZE 10 /* + terminator */
const char cfg_keywords[KWCOUNT][KWSIZE] = {
	"workdir",
	"cmdline",
	"environ",
	"respawn",
	"uid",
	"gid",
	"tty",
	"capable",
	"after",
	"wait",
	"faultless",
	"rlimit"
};

#define RLIMIT_COUNT 2
#define RLIMIT_NAME_MAX 16
struct rlimit_map
{
	int resource;
	char name[RLIMIT_NAME_MAX];
};
struct rlimit_map g_rlimit_map[RLIMIT_COUNT] = {
	{ RLIMIT_MEMLOCK, "memlock" },
	{ RLIMIT_RTPRIO,  "rtprio" },
};

struct program g_programs[MAX_PERSISTENT];
static char *program_relative_ptr(struct program *prg, char *ptr)
{
	return (char *)((size_t)ptr - (size_t)prg);
}
static char *program_absolute_ptr(struct program *prg, char *ptr)
{
	return (char *)((size_t)prg + (size_t)ptr);
}

/* convert in-flight relative pointers to absolute */
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

static int load_environ(struct program *prg, char *params, const size_t len)
{
	char *env_data;
	unsigned int count = 0;
	size_t pos = 0;
	unsigned int advance;

	/* copy data into struct */
	if (len >= PRG_ENVLEN) {
		printf("max envlen: %d\n", PRG_ENVLEN);
		return -1;
	}
	memcpy(prg->environ_data, params, len);
	prg->environ_data[len] = '\0';
	env_data = prg->environ_data;

	while (pos < len)
	{
		char *token;
		char *eq;

		token = eslib_string_toke(env_data, pos, len, &advance);
		if (token == NULL)
			break;

		pos += advance;
		eq = token;
		do {
			if (*eq == '=') {
				/* eq should not start or end token */
				if (eq == env_data || *(eq+1) == '\0')
					goto syntax_eq;
				break;
			}
			if (++eq >= env_data + len)
				goto syntax_eq;
		} while (*eq != '\0');
		if (*eq == '\0')
			goto syntax_eq;

		prg->environ[count] = program_relative_ptr(prg, token);

		if (++count > PRG_NUM_ENVIRON) {
			printf("max env vars: %d\n", PRG_NUM_ENVIRON);
			return -1;
		}
	}
	if (count == 0) {
		printf("no environment variables found\n");
		return -1;
	}
	return 0;
syntax_eq:
	printf("env var syntax error, missing or misplaced = operator\n");
	return -1;
}

/* setup binpath and argv */
static int load_cmdline(struct program *prg, char *params, const size_t len)
{
	char *binpath;
	char *cmdline_data;
	unsigned int count = 0;
	size_t pos = 0;
	unsigned int advance;

	if (len >= PRG_CMDLEN) {
		printf("max cmdlen: %d\n", PRG_CMDLEN);
		return -1;
	}

	memcpy(prg->cmdline, params, len);
	prg->cmdline[len] = '\0';
	cmdline_data = prg->cmdline;

	/* setup binpath and argv[0] */
	binpath = eslib_string_toke(cmdline_data, pos, len, &advance);
	pos += advance;
	if (binpath == NULL) {
		printf("cmdline missing binpath\n");
		return -1;
	}
	if (*binpath != '/') {
		printf("binpath must be absolute path starting with /\n");
		return -1;
	}
	prg->binpath = program_relative_ptr(prg, binpath);
	prg->argv[count++] = program_relative_ptr(prg, prg->name);

	/* setup args */
	while (pos < len)
	{
		char *token;

		token = eslib_string_toke(cmdline_data, pos, len, &advance);
		if (token == NULL)
			break;
		pos += advance;

		prg->argv[count] = program_relative_ptr(prg, token);
		if (++count > PRG_NUM_ARGUMENTS) {
			printf("max env vars: %d\n", PRG_NUM_ENVIRON);
			return -1;
		}
	}
	if (count == 0) {
		printf("no environment variables found\n");
		return -1;
	}
	return 0;
}

static int load_after(struct program *prg, char *params, const size_t len)
{
	char *after_name;
	unsigned int advance;
	size_t pos = 0;

	if (len >= PRG_NAMELEN) {
		printf("max namelen: %d\n", PRG_NAMELEN);
		return -1;
	}

	after_name = eslib_string_toke(params, pos, len, &advance);
	if (after_name == NULL) {
		printf("missing after program name\n");
		return -1;
	}
	if (strncmp(prg->name, after_name, PRG_NAMELEN) == 0) {
		printf("circular program ordering, impossible to resolve\n");
		return -1;
	}
	es_strcopy(prg->after, after_name, PRG_NAMELEN, NULL);
	return 0;

}

static int load_wait(struct program *prg, char *params, const size_t len)
{
	char *millisec;
	char *wait_file;
	unsigned int advance;
	uint32_t uint_read;
	size_t pos = 0;

	millisec = eslib_string_toke(params, pos, len, &advance);
	pos += advance;
	if (millisec == NULL) {
		printf("missing milliseconds\n");
		return -1;
	}

	if (eslib_string_to_u32(params, &uint_read, 10)) {
		printf("bad int value\n");
		return -1;
	}
	if (uint_read > PRG_MAX_SLEEP) {
		printf("sleep too long, (%d / %d)\n", uint_read, PRG_MAX_SLEEP);
		return -1;
	}
	prg->sleep = uint_read;

	wait_file = eslib_string_toke(params, pos, len, &advance);
	if (wait_file == NULL)
		return 0; /* no file, just sleep */

	if (wait_file[0] != '/') {
		printf("wait file must be an absolute path\n");
		return -1;
	}
	if (es_strcopy(prg->wait_file, wait_file, PRG_PATHLEN, NULL)) {
		printf("wait file path too long, max len is %d\n", PRG_PATHLEN);
		return -1;
	}

	return 0;
}

static int load_capabilities(struct program *prg, char *params, const size_t len)
{
	unsigned char *caps;
	char *capset;
	char *capname;
	size_t pos = 0;
	unsigned int advance;
	unsigned int i;

	if (len >= MAX_CAPLINE) {
		printf("max capline: %d\n", MAX_CAPLINE);
		return -1;
	}

	capset = eslib_string_toke(params, pos, len, &advance);
	pos += advance;
	if (capset == NULL)
		goto err_capset;

	if (strncmp(params, "ambient", 8) == 0) {
		caps = prg->a_capabilities;
	}
	else if (strncmp(params, "inherit", 10) == 0) {
		caps = prg->i_capabilities;
	}
	else if (strncmp(params, "unbound", 9) == 0) {
		caps = prg->b_capabilities;
	}
	else {
		goto err_capset;
	}

	while (pos < len)
	{
		int capnum;

		capname = eslib_string_toke(params, pos, len, &advance);
		if (capname == NULL)
			break;
		pos += advance;

		capnum = cap_getnum(capname);
		if (capnum < 0) {
			/* fully capable root */
			if (strncmp(capname, "FULLY_CAPABLE", 14) == 0) {
				for (i = 0; i < NUM_OF_CAPS; ++i)
					caps[i] = 1;
				return 0;
			}
			printf("unknown capname: %s\n", capname);
			return -1;
		}
		caps[capnum] = 1;
	}
	return 0;

err_capset:
	printf("capable missing set (ambient, inherit, or unbound)\n");
	return -1;
}

static int load_rlimit(struct program *prg, char *params, const size_t len)
{
	char *name;
	char *value;
	unsigned int i;
	unsigned int advance;
	unsigned int pos = 0;

	name = eslib_string_toke(params, pos, len, &advance);
	pos += advance;
	if (name == NULL) {
		printf("missing rlimit name\n");
		return -1;
	}
	value = eslib_string_toke(params, pos, len, &advance);
	if (value == NULL) {
		printf("missing rlimit value\n");
		return -1;
	}
	for (i = 0; i < RLIMIT_COUNT; ++i)
	{
		char *rname = g_rlimit_map[i].name;
		if (strncmp(rname, name, RLIMIT_NAME_MAX) == 0) {
			int res_id = g_rlimit_map[i].resource;
			int32_t rval; /* TODO: add 64bit conversion functions to eslib */
			if (res_id >= RLIMIT_NLIMITS)
				return -1;
			if (prg->rlimit[res_id].is_set) {
				printf("rlimit %s is set twice.\n", name);
				return -1;
			}
			if (eslib_string_to_s32(value, &rval, 10)) {
				printf("bad rlimit value: %s\n", value);
				return -1;
			}
			prg->rlimit[res_id].is_set = 1;
			prg->rlimit[res_id].val = rval;
			return 0;
		}
	}
	printf("unsupported rlimit: %s\n", name);
	return -1;
}

static int parse_tty(struct program *prg, char *params, const size_t len)
{
	int32_t ttynum;
	int is_serial = 0;

	if (params[0] == 'S') {
		if (len <= 1) {
			return -1;
		}
		params += 1; /* allow S for ttyS* serial */
		is_serial = 1;
	}
	if (eslib_string_to_s32(params, &ttynum, 10)) {
		printf("bad tty number\n");
		return -1;
	}
	if (ttynum >= INT32_MAX) {
		printf("tty number too big\n");
		return -1;
	}
	else if (ttynum < 0) {
		printf("TODO negative tty for logging daemons/etc \n");
		return -1;
	}
	else if (!is_serial && ttynum == 0) {
		printf("tty0 not supported\n");
		return -1;
	}
	if (is_serial) {
		if (es_sprintf(prg->ttynum, PRG_TTYLEN, NULL, "S%d", ttynum))
			return -1;
	}
	else {
		if (es_sprintf(prg->ttynum, PRG_TTYLEN, NULL, "%d", ttynum))
			return -1;
	}
	return 0;
}

static int load_parameters(struct program *prg, int kw, char *params, const size_t len)
{
	int32_t int_read;
	uint32_t uint_read;

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
		if (es_strcopy(prg->workdir, params, PRG_PATHLEN, NULL)) {
			printf("workdir\n");
			return -1;
		}
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
		if (load_cmdline(prg, params, len)) {
			printf("load_cmdline failed\n");
			return -1;
		}
		break;

	case KW_ENVIRON:
		if (load_environ(prg, params, len)) {
			printf("load_environ failed\n");
			return -1;
		}
		break;

	case KW_RESPAWN:
		if (eslib_string_to_s32(params, &int_read, 10)) {
			printf("bad int value\n");
			return -1;
		}
		if (int_read < -1) {
			printf("bad respawn value, use -1 for infinite\n");
			return -1;
		}
		if (int_read >= INT32_MAX) {
			printf("bad respawn value, use -1 for infinite\n");
			return -1;
		}
		prg->respawn = int_read;
		break;

	case KW_UID:
		if (eslib_string_to_u32(params, &uint_read, 10)) {
			printf("bad int value\n");
			return -1;
		}
		if (uint_read > USERID_MAX) {
			printf("uid too big\n");
			return -1;
		}
		prg->uid = uint_read;
		break;

	case KW_GID:
		if (eslib_string_to_u32(params, &uint_read, 10)) {
			printf("bad int value\n");
			return -1;
		}
		if (uint_read > GROUPID_MAX) {
			printf("gid too big\n");
			return -1;
		}
		prg->gid = uint_read;
		break;

	case KW_TTY:
		if (parse_tty(prg, params, len)) {
			printf("parse_tty\n");
			return -1;
		}
		break;

	case KW_CAPABLE:
		if (load_capabilities(prg, params, len)) {
			printf("load_capabilities\n");
			return -1;
		}
		break;

	case KW_AFTER:
		if (load_after(prg, params, len)) {
			printf("load_after\n");
			return -1;
		}
		break;

	case KW_WAIT:
		if (load_wait(prg, params, len)) {
			printf("load_wait\n");
			return -1;
		}
		break;
	case KW_RLIMIT:
		if (load_rlimit(prg, params, len)) {
			printf("load_rlimit\n");
			return -1;
		}
		break;
	default:
		printf("invalid keyword\n");
		return -1;
	}
	return 0;
}

static int get_keyword(char *kw)
{
	unsigned int i = 0;
	for (; i < KWCOUNT; ++i)
	{
		if (strncmp(cfg_keywords[i], kw, KWSIZE) == 0)
			return i;
	}
	return -1;
}

static int program_parse_config(struct program *prg_out, char *filename,
		char *fbuf, const size_t flen)
{
	struct program newprg;
	unsigned int line_num = 0;
	size_t fpos = 0;

	if (flen == 0) {
		printf("config file is empty\n");
		return -1;
	}

	memset(&newprg, 0, sizeof(struct program));
	if (es_strcopy(newprg.name, filename, PRG_NAMELEN, NULL))
		return -1;
	if (es_strcopy(prg_out->name, filename, PRG_NAMELEN, NULL))
		return -1; /* save name for non-fatal faults */

	/* set defaults */
	newprg.respawn = 0;
	newprg.uid = USERID_MAX;
	newprg.gid = GROUPID_MAX;
	newprg.pid = 0;

	while (fpos < flen)
	{
		char *line;
		char *keyword = NULL;
		char *param = NULL;
		unsigned int linepos = 0;
		unsigned int linelen;
		unsigned int advance;
		int kw;

		line = &fbuf[fpos];
		++line_num;

		linelen = eslib_string_linelen(line, flen - fpos);
		if (linelen >= flen - fpos) {
			printf("bad line\n");
			return -1;
		}
		else if (linelen == 0) { /* blank line */
			++fpos;
			continue;
		}
		if (line[0] == '#') { /* comment */
			fpos += linelen + 1;
			continue;
		}
		if (!eslib_string_is_sane(line, linelen)) {
			printf("invalid line(%d){%s}\n", *line, line);
			return -1;
		}
		if (eslib_string_tokenize(line, linelen, " \t")) {
			printf("tokenize failed\n");
			return -1;
		}

		keyword = eslib_string_toke(line, linepos, linelen, &advance);
		linepos += advance;
		if (keyword == NULL) { /* only tabs/spaces on line */
			fpos += linelen + 1;
			continue;
		}
		kw = get_keyword(line);
		if (kw < 0) {
			printf("unknown keyword %s\n", line);
			return 1;
		}

		param = eslib_string_toke(line, linepos, linelen, &advance);
		linepos += advance;
		/* keywords without parameters at the top */
		if (kw == KW_FAULTLESS) {
			newprg.faultless = 1;
		}
		else if (param == NULL) {
			printf("missing parameters for keyword %s\n", keyword);
			return 1;
		}
		else if (load_parameters(&newprg, kw, param, linelen - (param - line))) {
			printf("load_parameters failed on line %d\n", line_num);
			return 1;
		}

		fpos += linelen + 1;
		if (fpos > flen) {
			printf("fpos > flen\n");
			return -1;
		}
		else if (fpos == flen)
			break;
	}

	if (newprg.workdir[0] != '/') {
		printf("workdir is missing\n");
		return 1;
	}
	if (newprg.binpath == NULL) {
		printf("cmdline is missing\n");
		return 1;
	}
	memcpy(prg_out, &newprg, sizeof(struct program));
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
	size_t flen;
	int fd;
	int r;

	memset(fbuf, 0, sizeof(fbuf));
	memset(prg, 0, sizeof(struct program));

	/* assemble path */
	r = es_sprintf(cfg_path,sizeof(cfg_path),NULL,"%s/%s",PRG_CONFIGS_DIR,filename);
	if (r) {
		printf("program config path too long: %s\n", cfg_path);
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
	flen = r;

	/* fill out program struct */
	return program_parse_config(prg, filename, fbuf, flen);
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
	if (len >= PRG_NAMELEN) {
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
			printf("max config name length is %d\n", PRG_NAMELEN);
			goto failure;
		}

		r = program_load_config(&prg, dent->d_name);
		if (r > 0) {
			printf("fault: program config error: %s\n", dent->d_name);
			prg.status |= PRG_STATUS_FAULT;
		}
		if (r < 0)
			goto failure;

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
