/* (c) 2017 Michael R. Tirado -- GPLv3+
 * GNU General Public License, version 3 or any later version.
 * contact: mtirado418@gmail.com
 *
 *
 * initram /init program, load modules, mount/chroot, exec /sbin/init
 * TODO this should really be static linked
 *
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <syscall.h>

#include "eslib/eslib.h"

#ifndef MAX_SYSTEMPATH
	#define MAX_SYSTEMPATH 1023
#endif
#ifndef DEFAULT_INIT
	#define DEFAULT_INIT "/sbin/init"
#endif

#define ROOT_MNTPOINT "/newrootfs"

/* will spawn a rescue shell if init fails, in a workable state */
#ifndef CAN_COMMANDEER
	#define CAN_COMMANDEER 0
#endif
#ifndef ALWAYS_COMMANDEER
	#define ALWAYS_COMMANDEER 0
#endif
/* NOTE: depending on caller location this could be sh from initramfs or rootfs */
#ifndef COMMANDEER_SHELL
	#define COMMANDEER_SHELL "/bin/sh"
#endif


extern char *get_cmdline(const char *param, unsigned int *out_len);
extern char get_modman_mode();
char *nullp[] = { NULL, NULL };

static int panic()
{
	printf("\ninitram catastrophe.\n");
	while (1)
	{
		usleep(1000000);
	}
	_exit(-1);
	return -1;
}

static int recurse_rm(char *path)
{
	char next_path[MAX_SYSTEMPATH];
	struct dirent *dent;
	DIR *dir;
	static int skipdev = 1;

	dir = opendir(path);
	if (dir == NULL) {
		printf("error opening dir %s: %s\n", path, strerror(errno));
		return -1;
	}
	while (1)
	{
		dent = readdir(dir);
		if (dent == NULL) {
			break;
		}
		/* XXX hack: skip files named dev (we need it to mount newroot) */
		if (skipdev) {
			if (strncmp(&dent->d_name[0], "dev", 4) == 0) {
				skipdev = 0;
				continue;
			}
		}
		/* skip . and .. */
		if (dent->d_name[0] == '.') {
			if (dent->d_name[1] == '\0') {
				continue;
			}
			else if (dent->d_name[1] == '.') {
				if (dent->d_name[2] == '\0')
					continue;
			}
		}

		if (es_sprintf(next_path, sizeof(next_path),
					NULL, "%s/%s", path, dent->d_name)) {
			printf("recurse pathlen error\n");
			continue;
		}
		if (dent->d_type == DT_DIR) {
			/* recurse through directories */
			recurse_rm(next_path);
			if (rmdir(next_path)) {
				printf("rmdir failed: %s\n", strerror(errno));
			}
		}
		else {
			/* unlink everything else */
			if(unlink(next_path)) {
				printf("unable to unlink: %s\n", next_path);
			}
		}
	}
	closedir(dir);
	return 0;
}


#define ROOTFS_COUNT 8
#define ROOTFS_SIZE 256
static int init_rootfs(const char *newroot)
{
	const char *rootfs_types[ROOTFS_COUNT] = {
		"ext2",
		"ext4",
		"ext3",
		"iso9660",
		"minix",
		"reiserfs",
		"jfs",
		"xfs"
		/* TODO add support for live systems
		"ramfs"  grows dynamically, unconstrained
		"tmpfs", need to set a size + can use swap */
	};
	unsigned int cmdlen;
	char *rootfs;
	unsigned int i = 0;
	struct stat st;

	/* TODO see how grub passes this, lilo sends us a number.
	 * only supporting node paths like /dev/sda1 right now */
	rootfs = get_cmdline("root=", &cmdlen);
	if (rootfs == NULL) {
		printf("missing root= kernel cmdline\n");
		return 1;
	}
	rootfs += 5; /* skip past root= */
	if (rootfs[0] != '/' || strnlen(rootfs, ROOTFS_SIZE) >= ROOTFS_SIZE) {
		printf("bad cmdline root=%s\n", rootfs);
		return 1;
	}
	if (stat(rootfs, &st)) {
		printf("stat rootfs(%s): %s\n", rootfs, strerror(errno));
		return 1;
	}
	if (!S_ISBLK(st.st_mode)) {
		printf("root is not a block device: %s\n", rootfs);
		return 1;
	}

	if (umount("/proc")) {
		printf("umount(/proc): %s\n", strerror(errno));
	}
	/* unlink everything (except /dev) to free up ram */
	if (recurse_rm("/")) {
		return 1;
	}

	/* setup newrootfs mount point */
	if (mkdir(newroot, 0755)) {
		if (errno != EEXIST) {
			printf("mkdir(%s): %s\n", newroot, strerror(errno));
			return -1;
		}
	}
	for (i = 0; i < ROOTFS_COUNT; ++i)
	{
		if (mount(rootfs, newroot, rootfs_types[i], MS_RDONLY, NULL)==0) {
			printf("(%s)rootfs mounted as %s\n", rootfs, rootfs_types[i]);
			break;
		}
	}
	if (i >= ROOTFS_COUNT) {
		printf("could not mount rootfs, unknown type\n");
		return -1;
	}
	return 0;
}

static int commandeer_or_panic()
{
	if (!CAN_COMMANDEER)
		return panic();
	printf("\n");
	printf("\n");
	printf("initramfs: /init calling execve(%s)\n", COMMANDEER_SHELL);
	printf("attempting to spawn an interactive shell on /dev/console\n");
	printf("to get a proper terminal you should open /dev/tty1 and set TERM var\n");
	printf("e.g:\n");
	printf("setsid /bin/sh -c 'exec /bin/sh </dev/tty1 >/dev/tty1 2>/dev/tty1'\n");
	printf("export TERM=linux\n");
	printf("\n");
	printf("\n");
	if (execve(COMMANDEER_SHELL, nullp, nullp))
		printf("exec(%s): %s\n", COMMANDEER_SHELL, strerror(errno));
	return panic();
}

/* open /dev/console if we don't have stdio descriptors setup */
static int check_console()
{
	struct stat st;

	if (fstat(STDIN_FILENO, &st)
			|| fstat(STDOUT_FILENO, &st)
			|| fstat(STDERR_FILENO, &st)) {
		int fd;
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		fd = open("/dev/console", O_RDWR, 0);
		if (fd < 0) {
			return -1;
		}
		if (dup2(fd, STDIN_FILENO) != STDIN_FILENO
				|| dup2(fd, STDOUT_FILENO) != STDOUT_FILENO
				|| dup2(fd, STDERR_FILENO) != STDERR_FILENO) {
			printf("/dev/console: dup2(): %s\n", strerror(errno));
			return -1;
		}
		if (fd > STDERR_FILENO) {
			close(fd);
		}
	}
	return 0;
}

int main()
{
	char init_cmd[MAX_SYSTEMPATH];
	char *cmd = NULL;
	unsigned int cmdlen;
	int nosys  = 0;
	int noproc = 0;
	int r;

	mkdir("/proc", 0755);
	mkdir("/sys", 0750);
	mkdir("/dev", 0755);

	mount(NULL, "/dev", "devtmpfs", MS_NOEXEC, NULL);
	if (check_console())
		return panic(); /* TODO: consoleless ? */
	if (mount(NULL, "/proc", "proc", MS_NODEV|MS_NOEXEC, NULL)) {
		printf("could not mount /proc\n");
		noproc = 1;
	}
	if (mount(NULL, "/sys", "sysfs", MS_NODEV|MS_NOEXEC, NULL)) {
		printf("could not mount /sys\n");
		nosys = 1;
	}

	memset(init_cmd, 0, sizeof(init_cmd));
	cmd = get_cmdline("init=", &cmdlen);
	if (cmd) {
		cmd += 5;
		if (cmdlen < sizeof(init_cmd)) {
			es_strcopy(init_cmd, cmd, sizeof(init_cmd), NULL);
		}
		else {
			printf("ignoring init= cmdline, path too long\n");
		}
	}
	if (!nosys) {
		/*
		 * TODO drop libc dependency
		 * TODO, C module loader, and check modman params until then
		 * don't care if it fails, system may or may not boot with builtin modules
		 */
		switch (get_modman_mode())
		{
			case 'a': system("/sbin/modman.sh -a"); break;
			case 'w': system("/sbin/modman.sh -w"); break;
			case 'i': system("/sbin/modman.sh -i"); break;
			default: return commandeer_or_panic();
		}
		if (umount("/sys")) {
			printf("umount(/sys): %s\n", strerror(errno));
		}
	}

	if (ALWAYS_COMMANDEER || get_cmdline("commandeer", &cmdlen)) {
		return commandeer_or_panic();
	}
	if (noproc) { /* depends on root=  cmdline */
		return commandeer_or_panic();
	}


	/* mount rootfs and begin unlinking initramfs system */
	r = init_rootfs(ROOT_MNTPOINT);
	if (r) {
		printf("could not init rootfs\n");
		if (r > 0)
			return commandeer_or_panic();
		return panic();
	}


	/* -----> insert custom initram code here  <----- */

	/* remove remaining files from initramfs */
	/*if (umount("/dev")) {
		printf("umount(/dev): %s\n", strerror(errno));
	}
	if (recurse_rm("/dev")) {
		printf("recurse_rm(/dev): %s\n", strerror(errno));
		return panic();
	}*/

	if (chdir(ROOT_MNTPOINT) < 0) {
		printf("chdir(\"/\") failed: %s\n", strerror(errno));
		return panic();
	}
	if (chroot(ROOT_MNTPOINT)) {
		printf("chroot failed: %s\n", strerror(errno));
		return panic();
	}

	if (chdir("/") < 0) {
		printf("chdir(\"/\") failed: %s\n", strerror(errno));
		return commandeer_or_panic();
	}
	if (mount(NULL, "/dev", "devtmpfs", MS_NOEXEC|MS_NOSUID, NULL)) {
		printf("mount(/dev): %s\n", strerror(errno));
		return commandeer_or_panic();
	}

	if (init_cmd[0] != '\0') {
		if (execve(init_cmd, nullp, nullp))
			printf("exec(%s): %s\n", init_cmd, strerror(errno));
	}
	else {
		if (execve(DEFAULT_INIT, nullp, nullp))
			printf("exec(%s): %s\n", DEFAULT_INIT, strerror(errno));
	}
	return commandeer_or_panic();
}
