/* (c) Michael R. Tirado -- GPLv3 -- Gnu General Public License version 3
 * init.c
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
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
#define DEFAULT_PATH "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"
#endif

#ifndef CRASH_PANIC
#define CRASH_PANIC 1 /* panic kernel if shutdown fails */
#endif

/* TODO INSTALL SHADOW! */
#define TEST_UID 1000
#define TEST_GID 100

#ifndef PS_COUNT
#define PS_COUNT 4
#endif
#ifndef PS_PATHLEN
#define PS_PATHLEN 128
#endif
#ifndef PS_TTYLEN
#define PS_TTYLEN 5
#endif
#ifndef PS_NAMELEN
#define PS_NAMELEN 16
#endif
#ifndef PS_ARGLEN
#define PS_ARGLEN 128
#endif
#ifndef PS_ARGCOUNT
#define PS_ARGCOUNT 3
#endif

struct persistent {
	char name[PS_NAMELEN];
	char path[PS_PATHLEN];
	char args[PS_ARGLEN][PS_ARGCOUNT];
	char *argv[PS_ARGCOUNT+1];
	char ttynum[PS_TTYLEN];
	pid_t pid;
	uid_t uid;
	gid_t gid;
	off_t respawn; /* -1 for unlimited respawns */
};

extern char **environ;
extern int do_shutdown(int restart, int killall);
sig_atomic_t g_terminating;

#define TERM_SHUTDOWN 1 /* power down system */
#define TERM_REBOOT   2 /* reboot system */
#define TERM_KILL     3 /* kill all processes */
static void sighand(int signum)
{
	switch (signum)
	{
		case SIGUSR1:
			g_terminating = TERM_SHUTDOWN;
			break;
		case SIGUSR2:
			g_terminating = TERM_REBOOT;
			break;
		case SIGTERM:
		case SIGINT:
		case SIGQUIT:
			g_terminating = TERM_KILL;
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
	if (sigaction(SIGUSR1,  &sa, NULL))
		printf("sigaction: %s\n", strerror(errno));
	if (sigaction(SIGUSR2,  &sa, NULL))
		printf("sigaction: %s\n", strerror(errno));
}

static void panic()
{
	/* we can panic kernel, or infinite loop
	 * try a last ditch HALT before crashing
	 */
	reboot(RB_HALT_SYSTEM);
	if (CRASH_PANIC) {
		exit(-1);
	}
	else {
		while(1)
		{
			usleep(1000);
			reboot(RB_HALT_SYSTEM);
		}
	}
}

static void terminator()
{
	struct timespec request, remain;
	int status, millisec;
	pid_t p;

	printf("init: propagating termination signal\n");
	sync();
	kill(-1, SIGTERM);

	millisec = 10000;
	/* give programs 10 seconds to exit */
	while (--millisec >= 0)
	{
		request.tv_sec  = 0;
		request.tv_nsec = 1000000;
		remain.tv_sec   = 0;
		remain.tv_nsec  = 0;
re_sleep:
		errno = 0;
		if (nanosleep(&request, &remain)) {
			if (errno == EINTR) {
				request.tv_nsec = remain.tv_nsec;
				goto re_sleep;
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
	if (g_terminating != TERM_KILL) {
		if (do_shutdown((g_terminating == TERM_REBOOT), 1)) {
			panic();
		}
	}
	else { /* TERM_KILL doesn't shut down system */
		if (kill(-1, SIGKILL)) {
			printf("kill(-1, SIGTERM): %s\n", strerror(errno));
		}
	}
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

/* open_tty - set up tty device as stdio
 * based on mingetty open_tty
 * TODO test real serial console
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
			printf("%s: chown/chmod %s\n", ttypath, strerror(errno));
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
			printf("%s: cannot open tty: %s\n",
					ttypath, strerror(errno));
			return -1;
		}
		if (ioctl(fd, TIOCSCTTY, (void *)1)) {
			printf("%s: no controlling tty: %s\n",
					ttypath, strerror(errno));
			return -1;
		}
		printf("hang up\n");
		sigaction (SIGHUP, &sa_old, NULL);
	}

	/* Set up stdin/stdout/stderr. */
	if (dup2(fd, 0) != 0 || dup2(fd, 1) != 1 || dup2(fd, 2) != 2) {
		printf("%s: dup2(): %s\n", ttypath, strerror(errno));
		return -1;
	}
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

static int downgrade_process(uid_t uid, gid_t gid)
{
	int r = 0;
	if (gid != 0) {
		if (setregid(gid, gid)) {
			printf("setgid(%d): %s\n", gid, strerror(errno));
			r = -1;
		}
	}
	if (uid != 0) {
		if (setreuid(uid, uid)) {
			printf("setuid(%d): %s\n", uid, strerror(errno));
			r = -1;
		}
	}
	return r;
}
static pid_t spawn(char *ttynum, char *prog, char **args,  uid_t uid, gid_t gid)
{
	pid_t p;

	if (!ttynum || !prog)
		return -1;

	p = fork();
	if (p) {
		if (p == -1) {
			printf("fork(): %s\n", strerror(errno));
			return -1;
		}
		return p; /* TODO things could go wrong, we should have a way
			     to rate limit or clear frequent respawns */
	}

	/*
	 * TODO test hangup and clear on VT's
	 * and add emergency shell (compile time) option. */
	if (open_tty(ttynum, 1, 0)) {
		printf("error: could not open tty%s\n", ttynum);
		_exit(-1);
	}
	if (downgrade_process(uid, gid)) {
		_exit(-1);
		printf("error: could not set uid\n");
	}
	if (execve(prog, args, environ)) {
		printf("exec(%s): %s\n", prog, strerror(errno));
	}
	_exit(-1);
}

static void persistent_initargs(struct persistent *persist)
{
	int i;
	for (i = 0; i < PS_ARGCOUNT; ++i)
	{
		persist->argv[i] = persist->args[i];
	}
	persist->argv[PS_ARGCOUNT] = NULL;
}

/* TODO rate limit?  output should go to syslog! */
static void respawn(struct persistent *persist)
{
	pid_t p;
	if (persist->respawn == 0 || persist->respawn < -1) {
		printf("respawns depleted\n");
		memset(persist, 0, sizeof(struct persistent));
		return;
	}

	p =  spawn(persist->ttynum,
		   persist->path,
		   persist->argv,
		   persist->uid,
		   persist->gid);
	if (p == -1) {
		printf("respawn error: %s\n", strerror(errno));
		memset(persist, 0, sizeof(struct persistent));
		return;
	}
	persist->pid = p;
	if (persist->respawn > 0)
		--persist->respawn;
	return;
}

static void post_exec(struct persistent *persist, pid_t p)
{
	int i;
	for (i = 0; i < PS_COUNT; ++i)
	{
		if (persist[i].pid == p)
		{
			respawn(&persist[i]);
			return;
		}
	}
}

static void wait_loop(struct persistent *persist)
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
			usleep(3000000);
		}
		else if (p) {
			post_exec(persist, p);
		}
	}
}




int main()
{
	struct persistent persist[PS_COUNT];
	char *args[3] = {NULL, NULL, NULL};
	pid_t p;

	g_terminating = 0;
	memset(&persist, 0, sizeof(persist));
	setsid();
	umask(022);
	setenv("PATH", DEFAULT_PATH, 1);
	setenv("TERM", "dumb", 1);
	setenv("USER", "root", 1);
	setenv("LOGNAME", "root", 1);
	setenv("HOME", "/root", 1);
	chdir("/root");
	sigsetup();

	/* TODO fsck broken as fsck */
	if (initialize()) {
		char c = '\0';
		printf("\n");
		printf("***************************************************\n");
		printf("    system init failed, continue anyway? (y/n)\n");
		printf("***************************************************\n");
		if (getch(&c) || (c != 'y' && c != 'Y')) {
			if (reboot(RB_POWER_OFF)) {
				panic();
			}
			_exit(-1);
		}
	}
	/* serial root ( ctrl-alt-2 in qemu ) */
	if (spawn("S0", "/bin/bash", args, 0, 0) == -1)
		printf("couldn't spawn ttyS0\n");

	/* root shells */
	setenv("TERM", "linux", 1);
	if (spawn("1", "/usr/bin/gtscreen", args, 0, 0) == -1)
		printf("couldn't spawn tty1\n");
	if (spawn("2", "/bin/bash", args, TEST_UID, TEST_GID) == -1)
		printf("couldn't spawn tty2\n");

	/* spawn user shell */
	setenv("USER", "user", 1);
	setenv("LOGNAME", "user", 1);
	setenv("HOME", "/home/user", 1);
	chdir("/home/user");
	args[0] = "spr16_example";
	args[1] = "tty1";
	args[2] = NULL;
	snprintf(persist[0].ttynum, PS_TTYLEN, "3");
	snprintf(persist[0].name, PS_NAMELEN, "spr16_example");
	snprintf(persist[0].path, PS_PATHLEN, "/usr/bin/spr16_example");
	snprintf(persist[0].args[0], PS_PATHLEN, args[0]);
	snprintf(persist[0].args[1], PS_PATHLEN, args[1]);
	persist[0].respawn = -1;
	persist[0].uid = TEST_UID;
	persist[0].gid = TEST_GID;
	persistent_initargs(&persist[0]);
	p = spawn("3", "/usr/bin/spr16_example", args, TEST_UID, TEST_GID);
	if (p == -1) {
		printf("couldn't spawn tty3\n");
	}
	persist[0].pid = p;

	wait_loop(persist);
	return -1;
}

