#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

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

/* TODO, option to set respawn counter in environ */
int main(int argc, char *argv[])
{
	char mode = 0;
	getpid();

	if (argc < 1) {
		printf("bad argument count\n");
		return -1;
	}
	else if (argc >= 2) {
		mode = argv[1][0];
	}

	printf("[%d] daemon spawned   mode=%c\n", pid, mode);
	switch (mode)
	{
		case 's':
			while(1)
			{
				usleep(100000000);
			}
			break;
		case 'i':
		default:
			print_info(argc, argv);
			break;
	}
	printf("[%d] %s exiting\n", pid, argv[0]);
	return 0;
}
