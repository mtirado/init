/* (c) 2017 Michael R. Tirado GPLv3+
 * GNU General Public License, version 3 or any later version.
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

char tmpbuf[4096];
char *get_cmdline(const char *param, unsigned int *out_len)
{
	char cmdline[4096]; /* as of linux 4.8, largest COMMAND_LINE_SIZE */
	unsigned int i;
	unsigned int param_len;
	unsigned int size;
	int r;
	int fd;

	*out_len = 0;
	param_len = strnlen(param, 128);
	if (param_len >= 128)
		return NULL;

	/* read cmdline */
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd == -1) {
		printf("open(/proc/cmdline): %s\n", strerror(errno));
		return NULL;
	}
	memset(cmdline, 0, sizeof(cmdline));
	r = read(fd, cmdline, sizeof(cmdline)-1);
	if (r <= 0 || r >= (int)sizeof(cmdline)) {
		printf("read(/proc/cmdline): %s\n", strerror(errno));
		close(fd);
		return NULL;
	}
	close(fd);
	size = r;

	i = 0;
	do
	{
		if (cmdline[i] != param[0]) {
			while (++i < size)
			{
				if (cmdline[i] == '\n' || cmdline[i] == '\0')
					break;
			}
		}
		else if (!strncmp(param, &cmdline[i], param_len)){
			unsigned int start = i;
			while (++i < size)
			{
				if (cmdline[i] == '\n' || cmdline[i] == '\0') {
					unsigned int len = i - start;
					if (len >= sizeof(tmpbuf))
						return NULL;
					memset(tmpbuf, 0, sizeof(tmpbuf));
					strncpy(tmpbuf, &cmdline[start], len);
					*out_len = len;
					return tmpbuf;
				}
			}
		}
	}
	while (++i < size);

	return NULL;
}

char get_modman_mode()
{
	const char find_param[] = "modman.mode=";
	char *param_str;
	unsigned int cmdlen;

	param_str = get_cmdline(find_param, &cmdlen);
	if (param_str == NULL) {
		return 'n';
	}

	/* expects a single byte (where null terminator is in find_param) */
	if (cmdlen != sizeof(find_param)) {
		goto invalid;
	}
	param_str += cmdlen;
	switch (*param_str)
	{
		case 'a':
			return 'a';
		case 'w':
			return 'w';
		case 'i':
			return 'i';
	}
invalid:
	printf("modman: bad kernel cmdline param, defaulting to auto mode.\n");
	printf("usage:\n\n");
	printf("       auto mode: modman.mode=a\n");
	printf("  whitelist mode: modman.mode=w\n");
	printf("interactive mode: modman.mode=i\n");
	return 'a';
}
