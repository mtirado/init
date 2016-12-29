/* (c) 2015 Michael R. Tirado -- GPLv3, GNU General Public License, version 3.
 * contact: mtirado418@gmail.com
 *
 * shutdown.c
 */

#define _GNU_SOURCE
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include <linux/reboot.h>
#include <syscall.h>

#ifndef SHUTDOWN_PROGRAM
#define SHUTDOWN_PROGRAM "/etc/shutdown.sh"
#endif

/* wait after sigterm with -f option */
#ifndef TERMWAIT_SECONDS
#define TERMWAIT_SECONDS ((int)10)
#endif
/* 20 seconds-ish until fallback shutdown */
#ifndef SHUTDOWN_SECONDS
#define SHUTDOWN_SECONDS ((int)20)
#endif
#ifndef WAIT_SLICES
#define WAIT_SLICES  ((int)1000000)
#endif
#ifndef WAIT_SLICE
#define WAIT_SLICE   (WAIT_SLICES / SHUTDOWN_SECONDS)
#endif
#ifndef FALLBACK_WAITSYNC
#define FALLBACK_WAITSYNC 8
#endif

int call_reboot(unsigned int rb_action)
{
	return syscall( SYS_reboot,
			LINUX_REBOOT_MAGIC1,
			LINUX_REBOOT_MAGIC2,
			rb_action,
			NULL);
}

int do_shutdown(unsigned int rb_action, int killall)
{
	int slice;
	int status = 0;
	pid_t p;

	/*
	 * TODO make a nice killall function to use in force mode,
	 */
	if (killall) {
		if (kill(-1, SIGKILL)) {
			printf("kill(-1, SIGTERM): %s\n", strerror(errno));
		}
	}
	sync();
	usleep(500000);
	p = fork();
	if (p == 0) {
		char *args[] = { NULL, NULL };
		if (execve(SHUTDOWN_PROGRAM, args, environ)) {
			printf("exec(%s): %s\n", SHUTDOWN_PROGRAM, strerror(errno));
		}
		return -1;
	}
	else if (p == -1) {
		printf("fork(): %s\n", strerror(errno));
		return -1;
	}

	/* wait for shutdown program to finish */
	slice = WAIT_SLICES;
	while (--slice >= 0)
	{
		pid_t rp = waitpid(p, &status, WNOHANG);
		if (rp == 0) {
			struct timespec request, remain;
			request.tv_sec  = 0;
			request.tv_nsec = (1000000000/WAIT_SLICE);
			remain.tv_sec   = 0;
			remain.tv_nsec  = 0;
re_sleep:
			errno = 0;
			if (nanosleep(&request, &remain)) {
				if (errno == EINTR) {
					request.tv_sec  = 0;
					request.tv_nsec = remain.tv_nsec;
					goto re_sleep;
				}
				else {
					printf("nanosleep: %s\n", strerror(errno));
					return -1;
				}
			}
		}
		else if (rp == -1 && errno != EINTR) {
			printf("waitpid: %s\n", strerror(errno));
			return -1;
		}
		else if (rp == p) {
			break;
		}
	}
	if (slice < 0) {
		/* timed out, go to fallback */
		return -1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("shutdown script failed: %s\n", SHUTDOWN_PROGRAM);
		if (WIFEXITED(status)) {
			printf("exited: %d\n", WEXITSTATUS(status));
		}
		else if (WIFSIGNALED(status)) {
			printf("signalled: %d\n", WTERMSIG(status));
		}
		else {
			printf("failure: %d\n", status);
		}
		return -1;
	}

	if (rb_action == RB_AUTOBOOT) {
		if (call_reboot(RB_AUTOBOOT)) {
			printf("reboot: %s\n", strerror(errno));
		}
	}
	else if (rb_action == RB_HALT_SYSTEM) {
		if (call_reboot(RB_HALT_SYSTEM)) {
			printf("halt: %s\n", strerror(errno));
		}
	}
	else {
		if (call_reboot(RB_POWER_OFF)) {
			printf("shutdown: %s\n", strerror(errno));
		}
	}
	return -1;
}


/* TODO using "system" is far less than ideal.
 * use direct kernel calls, someday in the future.
 */
void shutdown_fallback(unsigned int rb_action)
{
	struct timespec request, remain;
	setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin", 1);
	printf("\n\n");
	printf("*********************************************\n");
	printf("         FALLBACK SHUTDOWN TRIGGERED         \n");
	printf("*********************************************\n");
	/* TODO killall */
	system("swapoff -a");
	printf("unmounting filesystems\n");
	sync();
	system("umount -v -a -r -t no,proc,sysfs");
	system("mount -v -n -o remount,ro /");
	printf("synchronizing storage devices\n");
	sync();

	request.tv_sec  = FALLBACK_WAITSYNC;
	request.tv_nsec = 0;
	remain.tv_sec   = 0;
	remain.tv_nsec  = 0;
re_sleep:
	errno = 0;
	if (nanosleep(&request, &remain)) {
		if (errno == EINTR) {
			request.tv_sec  = remain.tv_sec;
			request.tv_nsec = remain.tv_nsec;
			goto re_sleep;
		}
	}

	if (rb_action == RB_AUTOBOOT) {
		if (call_reboot(RB_AUTOBOOT)) {
			printf("reboot: %s\n", strerror(errno));
		}
	}
	else if (rb_action == RB_HALT_SYSTEM) {
		if (call_reboot(RB_HALT_SYSTEM)) {
			printf("halt: %s\n", strerror(errno));
		}
	}
	else {
		if (call_reboot(RB_POWER_OFF)) {
			printf("shutdown: %s\n", strerror(errno));
		}
	}
}


#ifndef STRIP_MAIN
static int request_shutdown(unsigned int rb_action)
{
	/* reboot */
	if (rb_action == RB_AUTOBOOT) {
		if (kill(1, SIGUSR2) == 0) {
			return 0;
		}
	} /* halt */
	else if (rb_action == RB_HALT_SYSTEM) {
		if (kill(1, SIGHUP) == 0) {
			return 0;
		}
	} /* poweroff */
	else {
		if (kill(1, SIGUSR1) == 0) {
			return 0;
		}
	}
	printf("shutdown request failed, kill: %s\n", strerror(errno));
	return -1;
}

static void sig_setup()
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN; sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = SIG_IGN; sigaction(SIGILL,  &sa, NULL);
	sa.sa_handler = SIG_IGN; sigaction(SIGABRT, &sa, NULL);
	sa.sa_handler = SIG_IGN; sigaction(SIGHUP,  &sa, NULL);
	sa.sa_handler = SIG_IGN; sigaction(SIGFPE,  &sa, NULL);
	sa.sa_handler = SIG_IGN; sigaction(SIGSEGV, &sa, NULL);
	sa.sa_handler = SIG_IGN; sigaction(SIGALRM, &sa, NULL);
	sa.sa_handler = SIG_IGN; sigaction(SIGBUS,  &sa, NULL);
	sa.sa_handler = SIG_IGN; sigaction(SIGSYS,  &sa, NULL);
	sa.sa_handler = SIG_IGN; sigaction(SIGPIPE, &sa, NULL);
	sa.sa_handler = SIG_IGN; sigaction(SIGQUIT, &sa, NULL);
}

int main(int argc, char **argv)
{
	unsigned int rb_action = RB_POWER_OFF;
	int should_reboot = 0;
	int should_halt = 0;
	int immediate = 0;
	int stealth = 0;
	int force = 0;
	char c = 0;

	sig_setup();

	while((c = getopt(argc,argv, "prhfZs")) != -1)
	{
		switch(c)
		{
		case 'p':
			/* power off */
			break;
		case 'r':
			should_reboot = 1;
			break;
		case 'h':
			should_halt = 1;
			break;
		case 'f':
			force = 1;
			break;
		case 's':
			stealth = 1;
			force = 1;
			break;
		case 'Z': /* Zeriously dangerous */
			immediate = 1;
			break;
		default:
			printf("usage:\n");
			printf("shutdown -p power off\n");
			printf("shutdown -h halt\n");
			printf("shutdown -r reboot\n");
			printf("shutdown -f force (dont signal, use direct syscall\n");
			printf("shutdown -s stealth, no sigterm (implies -f)");
			printf("shutdown -Z immediate dangerous shutdown");
			_exit(1);
			break;
		}
	}
	rb_action = RB_POWER_OFF;
	if (should_reboot) {
		rb_action = RB_AUTOBOOT;
	}
	if (should_halt) {
		rb_action = RB_HALT_SYSTEM;
	}
	if (immediate) {
		if (call_reboot(rb_action)) {
			printf("reboot: %s\n", strerror(errno));
		}
		_exit(-1);
	}
	sync();

	/* shutdown directly instead of signalling init */
	if (force) {
		struct timespec request, remain;
		int sec;
		if (!stealth) {
			if (kill(-1, SIGTERM)) {
				printf("kill(-1, SIGTERM): %s\n", strerror(errno));
			}
			sec = TERMWAIT_SECONDS;
			while (--sec >= 0) {
				request.tv_sec  = 1;
				request.tv_nsec = 0;
				remain.tv_sec   = 0;
				remain.tv_nsec  = 0;
re_sleep:
				errno = 0;
				if (nanosleep(&request, &remain)) {
					if (errno == EINTR) {
						request.tv_sec  = remain.tv_sec;
						request.tv_nsec = remain.tv_nsec;
						goto re_sleep;
					}
				}
			}
		}
		if (do_shutdown(rb_action, 0)) {
			shutdown_fallback(rb_action);
			_exit(-1);
		}
	} /* signal init to handle shutdown */
	else {
		if (request_shutdown(rb_action)) {
			_exit(-1);
		}
	}
	_exit(-1);
}

#endif

