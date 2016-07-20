/* (c) Michael R. Tirado -- GPLv3 -- Gnu General Public License version 3
 *
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef INIT_PROGRAM
	#define INIT_PROGRAM "/etc/init.sh"
#endif
#ifndef DEFAULT_PATH
	#define DEFAULT_PATH "/sbin:/bin:/usr/sbin:/usr/bin"
#endif


extern char **environ;
sig_atomic_t g_terminating;

static void sighand(int signum)
{
	switch (signum)
	{
		/*
		case SIGUSR1:
		case SIGUSR2:
			break;*/
		case SIGTERM:
		case SIGINT:
		case SIGQUIT:
			sync();
			g_terminating = 1;
			break;
		default:
			break;
	}
}
/* catch basic termination sigs */
static void sigsetup()
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sighand;
	sigaction(SIGTERM,  &sa, NULL);
	sigaction(SIGQUIT,  &sa, NULL);
	sigaction(SIGINT,   &sa, NULL);
	/*
	sigaction(SIGUSR1,  &sa, NULL);
	sigaction(SIGUSR2,  &sa, NULL);*/
}

static void terminator()
{
	struct timespec request, remain;
	int i, status;
	pid_t p;

	printf("propagating termination signal\n");
	kill(-1, SIGTERM);

	/* give programs 10 seconds to exit */
	for (i = 0; i < 10; ++i)
	{
		request.tv_sec  = 1;
		request.tv_nsec = 0;
		remain.tv_sec   = 0;
		remain.tv_nsec  = 0;
re_sleep:
		errno = 0;
		if (nanosleep(&request, &remain)) {
			if (errno == EINTR) {
				request.tv_sec = remain.tv_sec;
				request.tv_nsec = remain.tv_nsec;
				goto re_sleep;
			}
			else {
				usleep(5000000);
				break;
			}
		}
re_wait:
		p = waitpid(-1, &status, WNOHANG);
		if (p == 0) {
			continue;
		}
		else if (p != -1) {
			goto re_wait;
		}
		else if (p == -1 && errno == ECHILD) {
			break;
		}
	}
	kill(-1, SIGKILL);
}

/* exec initialization process and look for 0 exit status */
int initialize()
{
	int status;
	pid_t p;

	p = fork();
	if (p == 0) {
		char *args[] = { NULL, NULL };
		if (execve(INIT_PROGRAM, args, environ)) {
			printf("exec(%s): %s\n", INIT_PROGRAM,strerror(errno));
		}
		return -1;
	}
	else if (p == -1) {
		printf("fork(): %s\n", strerror(errno));
		return -1;
	}

	while (1)
	{
		pid_t rp = waitpid(p, &status, 0);
		if (rp == -1 && errno != EINTR) {
			printf("waitpid: %s\n", strerror(errno));
			return -1;
		}
		else if (rp == p) {
			break;
		}
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("initialization failed: %s\n", INIT_PROGRAM);
		if (WIFEXITED(status)) {
			printf("exited: %d\n", WEXITSTATUS(status));
		}
		else if (WIFSIGNALED(status)) {
			printf("signalled: %d\n", WTERMSIG(status));
		}
		else {
			printf("unknown: %d\n", status);
		}
		return -1;
	}
	return 0;
}

static int getch(char *c)
{
	struct termios orig, tmp;
	if (!c)
		return -1;
	if (tcgetattr(STDIN_FILENO, &orig))
		return -1;
	memcpy(&tmp, &orig, sizeof(tmp));
	tmp.c_lflag &= ~(ICANON|ECHO);
	if (tcsetattr(STDIN_FILENO, TCSANOW, &tmp))
		return -1;
	if (read(STDIN_FILENO, c, 1) != 1) {
		printf("getch read(stdin): %s\n", strerror(errno));
		return -1;
	}
	if (tcsetattr(STDIN_FILENO, TCSANOW, &orig))
		return -1;
	return 0;
}

static int system_shutdown()
{
	/* TODO */
	printf ("..........\n");
	return -1;
}

static void wait_loop()
{
	while (1)
	{
		pid_t p;
		int status;

		if (g_terminating) {
			terminator();
			g_terminating = 0;
		}

		p = waitpid(-1, &status, 0);
		if (p == -1 && errno != EINTR) {
			usleep(1000000);
		}
	}
}


/* open_tty - set up tty device as stdio
 * based on mingetty open_tty
 * TODO serial console
 *
 */
static int open_tty(char *tty_num, int hangup, int clear)
{
	struct sigaction sa, sa_old;
	char ttypath[40];
	int fd;

	setsid();

	if (tty_num == NULL) {
		printf("null string passed to open_tty\n");
		return -1;
	}

	snprintf(ttypath, sizeof(ttypath), "/dev/tty%s", tty_num);
	printf("ttypath: %s\n", ttypath);

	if (chown(ttypath, 0, 0) || chmod(ttypath, 0600)) {
		if (errno != EROFS) {
			printf("%s: chown/chmod %s ", ttypath, strerror(errno));
			return -1;
		}
	}

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGHUP, &sa, NULL);

	fd = open(ttypath, O_RDWR, 0);
	if (fd < 0) {
		printf("%s: cannot open tty: %s\n", ttypath, strerror(errno));
		return -1;
	}
	if (ioctl(fd, TIOCSCTTY, (void *)1) == -1) {
		printf("%s: ioctl(TIOCSCTTY): %s\n",ttypath,strerror(errno));
		return -1;
	}
	if (!isatty(fd)) {
		printf("%s: not a tty\n", ttypath);
		return -1;
	}

	/* vhangup() will replace all open file descriptors in the kernel
	   that point to our controlling tty by a dummy that will deny
	   further reading/writing to our device. It will also reset the
	   tty to sane defaults, so we don't have to modify the tty device
	   for sane settings. We also get a SIGHUP/SIGCONT.
	   */
	if (hangup) {
		printf("calling hangup\n");
		if (vhangup()) {
			printf("%s: vhangup() failed\n", ttypath);
			return -1;
		}

		/* Get rid of the present stdout/stderr. */
		close(2);
		printf("close(2)\n");
		close(1);
		printf("close(1)\n");
		close(0);
		printf("close(0)\n");
		close(fd);

		fd = open(ttypath, O_RDWR, 0);
		if (fd < 0) {
			printf("%s: cannot open tty: %s",
					ttypath, strerror(errno));
			return -1;
		}
		if (ioctl(fd, TIOCSCTTY, (void *)1)) {
			printf("%s: no controlling tty: %s",
					ttypath, strerror(errno));
			return -1;
		}
		printf("hanged up\n");
		sigaction (SIGHUP, &sa_old, NULL);
	}

	printf("calling dup\n");
	/* Set up stdin/stdout/stderr. */
	if (dup2(fd, 0) != 0 || dup2(fd, 1) != 1 || dup2(fd, 2) != 2) {
		printf("%s: dup2(): %s\n", ttypath, strerror(errno));
		return -1;
	}
	printf("dup'd\n");
	if (fd > 2) {
		close(fd);
	}

	/* Write a reset string to the terminal. This is very linux-specific
	   and should be checked for other systems. */
	if (clear) {
		write(0, "\033[3;J", 5); /* clear scroll back */
		write(0, "\033c", 2);    /* reset */
	}

	return 0;

}

static int spawn(char *ttynum)
{
	char *args[] = { NULL, NULL };
	pid_t p;

	p = fork();
	if (p) {
		if (p == -1) {
			printf("fork(): %s\n", strerror(errno));
			return -1;
		}
		return 0;
	}

	/*
	 * XXX test hangup and VT's */
	if (open_tty(ttynum, 0, 0)) {
		/* XXX remove this later */
		printf("could not open tty1, using console");
	}
	if (execve("/bin/bash", args, environ)) {
		printf("exec(/bin/bash): %s\n", strerror(errno));
	}
	_exit(-1);
}

int main()
{
	g_terminating = 0;

	setsid();
	umask(022);
	setenv("PATH", DEFAULT_PATH, 1);
	setenv("TERM", "linux", 1);
	sigsetup();

	if (initialize()) {
		char c;
		printf("\n");
		printf("**************************************************\n");
		printf("system initialization failed, continue? (y/n)\n");
		printf("**************************************************\n");
		if (getch(&c) || (c != 'y' && c != 'Y')) {
			system_shutdown();
			wait_loop();
		}
	}
	if (spawn("1"))
		printf("couldn't spawn vt1");
	if (spawn("2"))
		printf("couldn't spawn vt2");
	if (spawn("3"))
		printf("couldn't spawn vt3");

	wait_loop();
	return -1;
}

