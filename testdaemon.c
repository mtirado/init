#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include "eslib/eslib.h"

extern char **environ;
pid_t pid;

static void print_info(int argc, char *argv[])
{
	int i;
	char **env = environ;

	printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	printf("[%d] process name: %s\n", pid, argv[0]);
	printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");

	for (i = 0; i < argc; ++i)
	{
		printf("[%d] argv[%d]: %s\n", pid, i, argv[i]);
	}
	i = 0;
	while (*env)
	{
		printf("[%d] env[%d]: %s\n", pid, i, *env);
		++env;
	}
}

int main(int argc, char *argv[])
{
	uint32_t count = 1;
	uint32_t i = 0;
	char mode = 0;
	char *wait_file = getenv("WAIT_FILE");

	pid_t pid = getpid();

	if (argc < 1) {
		printf("bad argument count\n");
		return -1;
	}
	else if (argc >= 2) {
		mode = argv[1][0];
	}
	if (argc >= 3) {
		if (eslib_string_to_u32(argv[2], &count, 10)) {
			printf("bad count argument\n");
		}
	}

	printf("[%d] %s spawned   mode=%c\n", pid, argv[0], mode);
	switch (mode)
	{
		case 's':
			for (i = 0; i < count; ++i)
				usleep(1000000);
			break;
		case 'i':
		default:
			print_info(argc, argv);
			break;
	}
	if (wait_file) {
		if (open(wait_file, O_CREAT|O_TRUNC|O_WRONLY, 0750) == -1)
			printf("wait_file(%s) open: %s\n", wait_file, strerror(errno));
		else
			printf("[%d] %s created wait_file %s\n", pid, argv[0], wait_file);
	}

	printf("[%d] %s exiting\n", pid, argv[0]);

	return 0;
}
