/* (c) 2017 Michael R. Tirado -- GPLv3+
 * GNU General Public License, version 3 or any later version.
 * contact: mtirado418@gmail.com
 *
 *
 *	some useful sysctls for init script
 *
 *	/proc/sys/kernel/sysctl_writes_strict = 1
 * 	/proc/sys/kernel/kptr_restrict = 1 (require CAP_SYSLOG for %pK addrs)
 * 	/proc/sys/kernel/dmsg_restrict = 1 (require CAP_SYSLOG for reading kmsg)
 * 	/proc/sys/kernel/yama/ptrace_scope = 1 (descendants only)
 * 	/proc/sys/fs/protected_symlinks = 1
 * 	/proc/sys/fs/protected_hardlinks = 1
 * 	/proc/sys/net/core/somaxconn = 128 (default was historically 128)
 *	/proc/sys/kernel/threads-max = 5000
 *	/proc/sys/kernel/randomize_va_space = 2 (ASLR default is 2)
 *	/proc/sys/kernel/pty/max = 1024
 *	/proc/sys/fs/pipe-max-size = 1048576
 *	/proc/sys/fs/nr_open  = 1048576  (upper limit)
 *	/proc/sys/fs/file-max = 16384    (systemwide default?)
 *	/proc/sys/fs/mqueue/msgsize_max = 1048576
 *	/proc/sys/fs/mqueue/queues_max = 100
 *	/proc/sys/fs/leases-enable = 0
 *	/proc/sys/fs/inofity/max_user_watches = 4096
 *	/proc/sys/fs/inofity/max_user_instances = 64
 *	/proc/sys/fs/inofity/max_queued_events = 16384
 *	/proc/sys/fs/inode-max/max_queued_events = 16384
 *	/proc/sys/fs/epoll/max_user_watches = 16384
 *	/proc/sys/fs/dir-notify-enable = 0
 *	/proc/sys/kernel/shm_rmid_forced =
 *	/proc/sys/kernel/shmall =
 *	/proc/sys/kernel/shmmax =
 *	/proc/sys/kernel/shmmni =
 *	etc...
 *
 * don't mind the numbers much here, they are too high for embedded
 * and too low for workstations/servers, check proc(5) manual for all the deets
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <linux/securebits.h>
#include <linux/capability.h>
extern int capset(cap_user_header_t header, cap_user_data_t data);

#include "eslib/eslib.h"
#include "program.h"

#ifndef INIT_PROGRAM
	#define INIT_PROGRAM "/etc/init.sh"
#endif
#ifndef DEFAULT_PATH
	#define DEFAULT_PATH "/sbin:/usr/sbin:/bin:/usr/bin"
#endif
#ifndef CRASH_PANIC
	#define CRASH_PANIC 0 /* exit pid1 on panic? */
#endif

/* attempt to keep going if program launcher fails */
#define PROGFAIL_NOPANIC

extern struct program g_programs[MAX_PERSISTENT];
extern char **environ;

/* cmdline.c */
extern char get_modman_mode();

/* shutdown.c */
extern int call_reboot(unsigned int rb_action);
extern int do_shutdown(unsigned int rb_action, int killall);
extern void shutdown_fallback(unsigned int rb_action);
sig_atomic_t g_terminating;
int g_firstspawn;
#define TERM_SHUTDOWN 1
#define TERM_REBOOT   2
#define TERM_HALT     3

static void sighand(int signum)
{
	switch (signum)
	{
		case SIGUSR1:
			g_terminating = TERM_HALT;
			break;
		case SIGUSR2:
			g_terminating = TERM_REBOOT;
			break;
		case SIGINT:
		case SIGHUP:
		case SIGTERM:
		case SIGQUIT:
			g_terminating = TERM_SHUTDOWN;
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

	/* ignore */
	sa.sa_handler = SIG_IGN;
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGFPE,  &sa, NULL);
	sigaction(SIGALRM, &sa, NULL);
	sigaction(SIGBUS,  &sa, NULL);
	sigaction(SIGSYS,  &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	/* handle */
	sa.sa_handler = sighand;
	sigaction(SIGTERM,  &sa, NULL);
	sigaction(SIGQUIT,  &sa, NULL);
	sigaction(SIGINT,   &sa, NULL);
	sigaction(SIGHUP,   &sa, NULL);
	if (sigaction(SIGUSR1,  &sa, NULL))
		printf("sigaction: %s\n", strerror(errno));
	if (sigaction(SIGUSR2,  &sa, NULL))
		printf("sigaction: %s\n", strerror(errno));
}

static void panic()
{
	/* we can panic kernel, or infinite loop */
	if (CRASH_PANIC) {
		exit(-1);
	}
	else {
		while(1)
		{
			call_reboot(RB_HALT_SYSTEM);
			kill(-1, SIGKILL);
			usleep(1000);
		}
	}
}

static void wait_millisec(const unsigned int millisec)
{
	struct timespec request, remain;
	unsigned int counter = 0;
	while (++counter <= millisec)
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
	}
}

static void terminator()
{
	unsigned int counter;
	unsigned int rb_action = RB_POWER_OFF;
	int status;
	pid_t p;

	printf("init: propagating termination signal\n");
	sync();
	kill(-1, SIGTERM);

	counter = 0;
	while (++counter <= 9000) /* 9+ seconds */
	{
		wait_millisec(1);
re_check:
		p = waitpid(-1, &status, WNOHANG);
		if (p > 1) {
			goto re_check;
		}
		else if (p == -1 && errno == ECHILD) {
			break;
		}
	}

	if (g_terminating == TERM_REBOOT)
		rb_action = RB_AUTOBOOT;
	else if (g_terminating == TERM_SHUTDOWN)
		rb_action = RB_POWER_OFF;
	else if (g_terminating == TERM_HALT)
		rb_action = RB_HALT_SYSTEM;

	if (do_shutdown(rb_action, 1)) {
		shutdown_fallback(rb_action);
	}
	panic();
}

/* exec initialization process and look for 0 exit status */
static int initialize()
{
	int status;
	char modmode = 'n';
	pid_t p;

	p = fork();
	if (p == 0) {
		char *args[] = { NULL, NULL };

		mkdir("/sys", 0700);
		chmod("/sys", 0700);
		mkdir("/proc", 0700);

		if (mount(0,"/proc","proc", MS_NODEV|MS_NOSUID|MS_NOEXEC, 0)) {
			printf("unable to mount /proc: %s\n", strerror(errno));
		}

		/* load modules */
		modmode = get_modman_mode();
		if (modmode != 'n') {
			if (mount(0, "/sys", "sysfs", MS_NODEV|MS_NOSUID|MS_NOEXEC, 0)) {
				printf("unable to mount /sys: %s\n", strerror(errno));
			}
			switch (modmode)
			{
				case 'a': system("/sbin/modman.sh -a"); break;
				case 'w': system("/sbin/modman.sh -w"); break;
				case 'i': system("/sbin/modman.sh -i"); break;
				case 'n': break;
				default: return -1;
			}
		}
		if (execve(INIT_PROGRAM, args, environ)) {
			printf("exec(%s): %s\n", INIT_PROGRAM, strerror(errno));
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

static int close_stdin()
{
	int nullfd;

	nullfd = open("/dev/null", O_RDONLY, 0);
	if (nullfd < 0) {
		printf("cannot open /dev/null: %s\n", strerror(errno));
		return -1;
	}
	close(0);
	if (dup2(nullfd, 0) != 0) {
		printf("dup2(/dev/null): %s\n", strerror(errno));
		return -1;
	}
	if (isatty(0)) {
		return -1;
	}
	return 0;
}

/* open_tty - set up tty device as stdio
 * based on mingetty open_tty
 * TODO test real serial console
 */
static int open_tty(char *tty_num, int hangup, int clear)
{
	char ttypath[40];
	int fd;

	if (tty_num == NULL) {
		printf("null string passed to open_tty\n");
		return -1;
	}

	es_sprintf(ttypath, sizeof(ttypath), NULL, "/dev/tty%s", tty_num);
	if (chown(ttypath, 0, 0) || chmod(ttypath, 0600)) {
		printf("%s: chown/chmod %s\n", ttypath, strerror(errno));
		return -1;
	}

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
		close(1);
		close(0);
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

static int prg_set_caps(unsigned char *cap_b,
		    unsigned char *cap_e,
		    unsigned char *cap_p,
		    unsigned char *cap_i,
		    unsigned long secbits)
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct   data[2];
	unsigned int i;
	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));
	hdr.version = _LINUX_CAPABILITY_VERSION_3;

	for(i = 0; i < NUM_OF_CAPS; ++i)
	{
		if (cap_e && cap_e[i] == 1) {
			data[CAP_TO_INDEX(i)].effective |= CAP_TO_MASK(i);
		}
		if (cap_p && cap_p[i] == 1) {
			data[CAP_TO_INDEX(i)].permitted	|= CAP_TO_MASK(i);
		}
		if (cap_i && cap_i[i] == 1) {
			data[CAP_TO_INDEX(i)].inheritable |= CAP_TO_MASK(i);
		}

		/* clear bounding set unless requested or inheriting */
		if (cap_b && cap_b[i] == 1)
			continue;
		if (cap_i && cap_i[i] == 1)
			continue;
		if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0)) {
			if (i > CAP_LAST_CAP) {
				break;
			}
			else if (errno == EINVAL) {
				printf("cap not found: %d\n", i);
				return -1;
			}
			printf("PR_CAPBSET_DROP: %s\n", strerror(errno));
			return -1;
		}
	}

	if (secbits) {
		if (prctl(PR_SET_SECUREBITS, secbits)) {
			printf("prctl(): %s\n", strerror(errno));
			return -1;
		}
	}
	if (capset(&hdr, data)) {
		printf("capset: %s\n", strerror(errno));
		printf("cap version: %p\n", (void *)hdr.version);
		printf("pid: %d\n", hdr.pid);
		return -1;
	}
	return 0;
}

static int downgrade_process(struct program *prg)
{
	unsigned char  full_caps[NUM_OF_CAPS];
	unsigned char  e_caps[NUM_OF_CAPS];
	unsigned char  p_caps[NUM_OF_CAPS];
	unsigned char *a_caps = prg->a_capabilities;
	unsigned char *b_caps = prg->b_capabilities;
	unsigned char *i_caps = prg->i_capabilities;
	uid_t uid = prg->uid;
	gid_t gid = prg->gid;
	unsigned long secbits = 0;
	int inheriting = 0;
	int active_caps = 0;
	int once = 1;
	unsigned int i;

	memset(e_caps, 0, sizeof(e_caps));
	memset(p_caps, 0, sizeof(p_caps));
	memset(full_caps, 1, sizeof(full_caps));

	/* a and i cannot be mixed */
	for (i = 0; i < NUM_OF_CAPS; ++i) {
		if (i_caps[i]) {
			inheriting = 1;
			for (i = 0; i < NUM_OF_CAPS; ++i) {
				if (a_caps[i]) {
					printf("cannot mix ambient with inherit\n");
					return -1;
				}
			}
			break;
		}
	}

	for (i = 0; i < NUM_OF_CAPS; ++i) {
		if (a_caps[i]) {
			if (once) {
				/* raising ambient requires inheritable */
				if (prg_set_caps(full_caps, full_caps,
							full_caps, a_caps, 0)) {
					printf("prg_set_caps failed\n");
					return -1;
				}
				once = 0;
			}
			if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i, 0, 0)) {
				printf("prctl(CAP_AMBIENT_RAISE): %s\n", strerror(errno));
				return -1;
			}
			active_caps = 1;
			b_caps[i] = 1;
			i_caps[i] = 1;
		}
		if (i_caps[i]) {
			active_caps = 1;
			b_caps[i] = 1;
			e_caps[i] = 1;
			p_caps[i] = 1;
			if (uid == 0) {
				/* inheritable set for non-root users only */
				i_caps[i] = 0;
			}
		}
	}
	if (active_caps) {
		secbits |= SECBIT_NO_SETUID_FIXUP
			|  SECBIT_NO_SETUID_FIXUP_LOCKED;
	}

	if (gid && setresgid(gid, gid, gid)) {
		printf("setgid(%d): %s\n", gid, strerror(errno));
		return -1;
	}

	e_caps[CAP_SETUID] = 1;
	p_caps[CAP_SETUID] = 1;
	if (prg_set_caps(b_caps, e_caps, p_caps, i_caps, secbits)) {
		printf("prg_set_caps failed\n");
		return -1;
	}
	if (uid && setresuid(uid, inheriting ? 0 : uid, uid)) {
		printf("setuid(%d): %s\n", uid, strerror(errno));
		return -1;
	}
	if (active_caps) {
		/* prevents the inheriting 0 uid above from being carried over
		 * to saved-set on exec, this is not as important for ambient. */
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			printf("could not set no new privs:%s\n", strerror(errno));
			return -1;
		}
	}
	return 0;
}

static int check_permission(struct program *prg)
{
	struct stat st;
	char *binpath = prg->binpath;
	/* check binpath */
	if (stat(binpath, &st)) {
		printf("stat(%s): %s\n", binpath, strerror(errno));
		return -1;
	}
	/*  o+x */
	if (!(st.st_mode & S_IXOTH)) {
		int authorized = 0;
		/* g+x */
		if (prg->gid == st.st_gid) {
			if (st.st_mode & S_IXGRP)
				authorized = 1;
		}
		/* u+x */
		if (prg->uid == st.st_uid) {
			if (st.st_mode & S_IXUSR)
				authorized = 1;
		}
		if (!authorized) {
			printf("missing execute permission for %s\n", binpath);
			return -1;
		}
	}

	return 0;
}

static unsigned long usecs_elapsed(struct timespec last, struct timespec cur)
{
	struct timespec elapsed;
	unsigned long usec;

	if (cur.tv_sec < last.tv_sec
			|| (cur.tv_sec == last.tv_sec && cur.tv_nsec < last.tv_nsec)) {
		printf("error: clock seems to have gone backwards\n");
		return 0;
	}

	elapsed.tv_sec = cur.tv_sec - last.tv_sec;
	if (!elapsed.tv_sec) {
		elapsed.tv_nsec = cur.tv_nsec - last.tv_nsec;
		usec = elapsed.tv_nsec / 1000;
	}
	else {
		usec = ((1000000000 - last.tv_nsec) + cur.tv_nsec) / 1000;
		usec += (elapsed.tv_sec-1) * 1000000;
	}
	return usec;
}

static int check_spawn_timer(struct program *prg)
{
	struct timespec curtime;
	unsigned long usecs;

	if (g_firstspawn)
		return 0;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &curtime)) {
		if (clock_gettime(CLOCK_MONOTONIC, &curtime)) {
			memset(&prg->last_spawn, 0, sizeof(struct timespec));
			return -1;
		}
	}
	usecs = usecs_elapsed(prg->last_spawn, curtime);
	if (usecs <= PRG_RAPID_RESPAWN_USECS) {
		printf("***** PROGRAM RESPAWN ERROR *****\n");
		printf("rapid respawn detected, disabling %s.\n", prg->name);
		printf("TODO: option to bypass this timer\n");
		errno = ETIME;
		return -1;
	}
	return 0;
}

static int check_program(struct program *prg)
{
	unsigned int i;

	if (check_spawn_timer(prg))
		return -1;
	if (prg->name[0] == '\0' || prg->workdir[0] != '/' || prg->binpath[0] != '/')
		return -1;
	if (prg->name[PRG_NAMELEN-1] != '\0'
			|| prg->workdir[PRG_PATHLEN-1] != '\0'
			|| prg->cmdline[PRG_CMDLEN-1] != '\0'
			|| prg->environ_data[PRG_ENVLEN-1] != '\0'
			|| prg->ttynum[PRG_TTYLEN-1] != '\0') {
		return -1;
	}

	printf("\n");
	printf("------------------------------------------------------------\n");
	printf("load: %s\n", prg->name);
	printf("------------------------------------------------------------\n");
	if (prg->ttynum[0] == '\0') {
		printf("  stdout: /dev/console\n");
	}
	else
		printf("  stdio: /dev/tty%s\n", prg->ttynum);
	printf("  path: %s\n", prg->binpath);
	printf("  workdir: %s\n", prg->workdir);
	printf("  uid: %d\n", prg->uid);
	printf("  gid: %d\n", prg->gid);
	printf("  respawn: %d\n", prg->respawn);
	printf("  arguments: ");
	for (i = 0; i < PRG_NUM_ARGUMENTS; ++i)
	{
		if (prg->argv[i] == NULL)
			break;
		printf("%s ", prg->argv[i]);
	}
	printf("\n");
	printf("  environ: ");
	for (i = 0; i < PRG_NUM_ENVIRON; ++i)
	{
		if (prg->environ[i] == NULL)
			break;
		printf("%s ", prg->environ[i]);
	}
	printf("\n");

	if (check_permission(prg))
		return -1;
	return 0;
}

static int spawn(struct program *prg)
{
	pid_t p;
	if (check_program(prg))
		return -1;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &prg->last_spawn)) {
		if (clock_gettime(CLOCK_MONOTONIC, &prg->last_spawn)) {
			if (!g_firstspawn) {
				/* don't respawn any programs if the clock is busted */
				memset(&prg, 0, sizeof(struct program));
				return -1;
			}
			else {
				memset(&prg->last_spawn, 0, sizeof(struct timespec));
			}
		}
	}

	p = fork();
	if (p) {
		if (p == -1) {
			printf("fork(): %s\n", strerror(errno));
			return -1;
		}
		prg->pid = p;

		return 0; /* TODO things could go wrong, like a missing file. need a way
			     to rate limit or clear frequent respawns so console error
			     spam is actually readable. in the case of missing home we
			     can create it, missing workdir can use home as fallback
			     missing binary should clear respawn value and just fail */
	}


	setsid();

	if (prg->ttynum[0] != '\0') {
		if (open_tty(prg->ttynum, 1, 0)) {
			printf("error: could not open tty%s\n", prg->ttynum);
			_exit(-1);
		}
	}
	else {
		if (close_stdin()) {
			_exit(-1);
		}
	}
	if (chdir(prg->workdir)) {
		printf("chdir(%s): %s\n", prg->workdir, strerror(errno));
		_exit(-1);
	}
	if (downgrade_process(prg)) {
		_exit(-1);
		printf("error: could not set uid\n");
	}
	if (execve(prg->binpath, prg->argv, prg->environ)) {
		printf("exec(%s): %s\n", prg->binpath, strerror(errno));
	}
	_exit(-1);
}

/* TODO rate limit?  output should go to syslog! */
static void respawn(struct program *prg)
{
	if (prg->respawn == 0 || prg->respawn < -1) {
		memset(prg, 0, sizeof(struct program));
		return;
	}

	if (spawn(prg)) {
		printf("respawn error: %s\n", strerror(errno));
		memset(prg, 0, sizeof(struct program));
		return;
	}
	if (prg->respawn > 0)
		--prg->respawn;
	return;
}

static void post_task(struct program *prg, pid_t p)
{
	int i;
	for (i = 0; i < MAX_PERSISTENT; ++i)
	{
		if (prg[i].pid == p)
		{
			prg[i].pid = 0;
			respawn(&prg[i]);
			return;
		}
	}
}

static void wait_loop(struct program *prg)
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
			post_task(prg, p);
		}
	}
}

/* we may need a signal to say that program configs have changed
 * to read the updated changes, which go into effect next respawn
 * no file i/o happens in pid1 to avoid D state, so we fork and pipe
 * the program structs from a less crucial process.
 *
 * 	pid1 fork/wait
 * 	pid* send program
 * 		pid* write uint32_t program_count
 * 		pid* write(struct program) * program_count
 * 	pid* close/exit
 *	pid1 read(sizeof(program) * count)
 * 	pid1 close/return
 */

/* load program array and return count */
static int read_program_pipe(int fd, struct program *programs,
			     const unsigned int max_persistent)
{
	unsigned int i;
	unsigned int prog_count;
	unsigned int bytes_expected;
	int r;

	/* read count */
	do {
		r = read(fd, &prog_count, sizeof(prog_count));
	}
	while (r == -1 && errno == EINTR);
	if (r != sizeof(prog_count))
		goto failure;
	if (prog_count > max_persistent) {
		printf("too many programs (%d/%d)\n", prog_count, max_persistent);
		goto failure;
	}
	else if (prog_count == 0) {
		return 0;
	}

	bytes_expected = sizeof(struct program) * prog_count;
	i = 0;
	while (i < bytes_expected)
	{
		do {
			r = read(fd, ((char *)programs)+i, bytes_expected - i);
		}
		while (r == -1 && errno == EINTR);
		if (r > 0)
			i += r;
		else if (r == 0)
			break;
		else
			goto failure;
	}
	if (i != bytes_expected) {
		printf("error: read %d bytes, bytes_expected %d\n", i, bytes_expected);
		goto failure;
	}

	return (int)prog_count;
failure:
	memset(programs, 0, sizeof(struct program) * max_persistent);
	return -1;
}

static void insert_at(struct program *prg,
		      struct program *order[],
		      unsigned int idx,
		      const unsigned int count)
{
	struct program *insert = prg;
	unsigned int i;
	for (i = idx; i < count; ++i)
	{
		struct program *tmp = order[i];
		order[i] = insert;
		insert = tmp;
	}
}

/* FIXME, fully sort programs with same "after" to prevent programs inserted later
 * from delaying an earlier program that could have been run sooner.
 */
static int sort_order(struct program *prg,
		     struct program *order[],
		     const unsigned int count)
{
	unsigned int i;

	/* don't add twice */
	for (i = 0; i < count; ++i)
	{
		if (order[i] == NULL)
			break;
		if (strncmp(order[i]->name, prg->name, PRG_NAMELEN) == 0) {
			return 0;
		}
	}

	/* to front of list if no dependencies */
	if (prg->after[0] == '\0') {
		insert_at(prg, order, 0, count);
		return 0;
	}

	for (i = 0; i < count - 1; ++i)
	{
		if (order[i] == NULL) {
			break;
		}
		else if (!strncmp(order[i]->name, prg->after, PRG_NAMELEN)) {
			insert_at(prg, order, i+1, count);
			return 0;
		}
	}
	return -1; /* after was not found (yet) */
}



static int spawn_programs(struct program *programs, const unsigned int count)
{
	unsigned int i, z;
	struct program *order[MAX_PERSISTENT];

	memset(order, 0, sizeof(order));
	for(i = 0; i < count; ++i)
	{
		int not_finished = 0;
		for(z = 0; z < count; ++z)
			if (sort_order(&programs[z], order, count))
				not_finished = 1;
		if (not_finished == 0)
			break;
	}
	if (i >= count) {
		printf("problem sorting programs, circular dependency?\n");
		return -1;
	}

	for(i = 0; i < count; ++i)
	{
		if (order[i] == NULL) {
			return -1;
		}
		if (spawn(order[i])) {
			printf("spawn failed\n");
			return -1;
		}
	}
	return 0;

}

static int configs_dir_exists()
{
	struct stat st;
	if (stat(PRG_CONFIGS_DIR, &st))
		return 0;
	if (S_ISDIR(st.st_mode))
		return 1;
	return -1;
}

static int load_programs(struct program *programs, const unsigned int max_persistent)
{
	const unsigned int time_limit = 10000; /* 10+ seconds */
	unsigned int timer = 0;
	int status;
	int count;
	int r;
	pid_t p;
	int ipc[2];

	memset(programs, 0, sizeof(struct program) * max_persistent);

	r = configs_dir_exists();
	if (r < 0) {
		printf("expected directory at %s\n", PRG_CONFIGS_DIR);
		return -1;
	}
	else if (r == 0) {
		return 0;
	}

	if (pipe2(ipc, O_CLOEXEC)) {
		printf("pipe2(O_CLOEXEC): %s\n", strerror(errno));
		return -1;
	}
	p = fork();
	if (p == -1) {
		printf("fork(): %s\n", strerror(errno));
		close(ipc[0]);
		close(ipc[1]);
		return -1;
	}

	/* new process */
	if (p == 0) {
		close(ipc[0]);
		if (program_load_configs_dir(ipc[1])) {
			_exit(-1);
		}
		_exit(0);
	}

	/* pid 1 */
	close(ipc[1]);
	while (timer++ < time_limit)
	{
		pid_t wpid;
		wait_millisec(1);
		wpid = waitpid(p, &status, WNOHANG);
		if (wpid == p) {
			break;
		}
		else if (wpid < 0) {
			printf("waitpid(%d): %s\n", p, strerror(errno));
			goto close_err;
		}
	}
	if (timer >= time_limit) {
		kill(p, -9);
		printf("launcher(%d) seems to have stalled\n", p);
		goto close_err;
	}
	else if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("launcher(%d) exited abnormally with status %d \n", p, status);
		goto close_err;
	}

	count = read_program_pipe(ipc[0], programs, max_persistent);
	close(ipc[0]);
	if (count < 0) {
		printf("failed reading program config pipe\n");
		return -1;
	}
	else if (count == 0)
	{
		printf("no programs to load\n");
		return 0;
	}

	for (r = 0; r < count; ++r)
	{
		if (program_land(&programs[r]))
			panic();
	}
	return spawn_programs(programs, count);
close_err:
	close(ipc[0]);
	return -1;
}

int main()
{
	g_firstspawn = 1;
	g_terminating = 0;
	memset(&g_programs, 0, sizeof(g_programs));
	setsid();
	umask(022);
	setenv("PATH", DEFAULT_PATH, 1);
	setenv("TERM", "linux", 1);
	setenv("USER", "root", 1);
	setenv("LOGNAME", "root", 1);
	setenv("HOME", "/root", 1);
	mkdir("/root", 0750);
	chdir("/root");
	sigsetup();

	/* disable ctrl-alt-delete hair trigger reboot */
	call_reboot(RB_DISABLE_CAD);

	if (initialize()) {
		char c = '\0';
		printf("\n");
		printf("***************************************************\n");
		printf("   init phase 1 failed, continue anyway? (y/n)\n");
		printf("***************************************************\n");
		if (getch(&c) || (c != 'y' && c != 'Y')) {
			call_reboot(RB_POWER_OFF);
			panic();
		}
	}

	if (load_programs(g_programs, MAX_PERSISTENT)) {
		printf("load_programs critical failure\n");
#ifndef PROGFAIL_NOPANIC
		panic();
#endif
	}
	g_firstspawn = 0;

	/* now we wait! */
	wait_loop(g_programs);

	panic();
	return -1;
}

