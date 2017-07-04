/* (c) 2017 Michael R. Tirado -- GPLv3+
 * GNU General Public License, version 3 or any later version.
 * contact: mtirado418@gmail.com
 *
 *
 * initram /init program, load modules, mount/chroot, exec /sbin/init
 * TODO this should really be static linked or maybe use busybox
 *
 * TODO create /dev/console automatically and open stdio descriptors ?
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

#define ROOT_MNTPOINT "/newrootfs"
#ifndef MAX_SYSTEMPATH
	#define MAX_SYSTEMPATH 4095
#endif
#ifndef DEFAULT_INIT
	#define DEFAULT_INIT "/sbin/init"
#endif

extern char *get_cmdline(const char *param, unsigned int *out_len);
extern char get_modman_mode();
char *nullp[] = { NULL };

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

		snprintf(next_path, sizeof(next_path), "%s/%s", path, dent->d_name);
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

	rootfs = get_cmdline("root=", &cmdlen);
	if (rootfs == NULL) {
		printf("missing root= kernel cmdline\n");
		 /* TODO compile time live install/rescue system option !! */
		return -1;
	}
	rootfs += 5; /* skip past root= */
	if (rootfs[0] != '/' || strnlen(rootfs, ROOTFS_SIZE) >= ROOTFS_SIZE) {
		printf("bad cmdline root=%s\n", rootfs);
		return -1;
	}
	if (stat(rootfs, &st)) {
		printf("stat rootfs(%s): %s\n", rootfs, strerror(errno));
		return -1;
	}
	if (!S_ISBLK(st.st_mode)) {
		printf("root is not a block device: %s\n", rootfs);
		return -1;
	}

	if (umount("/proc")) {
		printf("umount(/proc): %s\n", strerror(errno));
		return -1;
	}
	/* unlink everything (except /dev) to free up ram */
	if (recurse_rm("/")) {
		return -1;
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

int main()
{
	int nosys  = 0;

	if (mount(NULL, "/proc", "proc", MS_NODEV|MS_NOEXEC, NULL)) {
		return panic();
	}
	if (mount(NULL, "/dev", "devtmpfs", MS_NOEXEC, NULL)) {
		return panic();
	}
	if (mount(NULL, "/sys", "sysfs", MS_NODEV|MS_NOEXEC, NULL)) {
		nosys = 1;
	}

	/* TODO drop libc dependency */
	/* TODO, C module loader, and check modman params until then
	 * don't care if it fails, system may or may not boot with builtin modules
	 */
	switch (get_modman_mode())
	{
		case 'a': system("./modman.sh -a"); break;
		case 'w': system("./modman.sh -w"); break;
		case 'i': system("./modman.sh -i"); break;
		default: return panic();
	}

	if (!nosys) {
		if (umount("/sys")) {
			printf("umount(/sys): %s\n", strerror(errno));
			return panic();
		}
	}

	if (init_rootfs(ROOT_MNTPOINT)) {
		printf("could not init rootfs\n");
		return panic();
	}



	/* -----> insert custom initram code here  <----- */


	/* remove remaining files from initramfs */
	if (umount("/dev")) {
		printf("umount(/dev): %s\n", strerror(errno));
		return panic();
	}
	if (recurse_rm("/dev")) {
		printf("recurse_rm(/dev): %s\n", strerror(errno));
		return panic();
	}

	/* ye ole chroot shuffle */
	if (chdir(ROOT_MNTPOINT) < 0) {
		printf("chdir(\"/\") failed: %s\n", strerror(errno));
		return panic();
	}
	/*if (mount(ROOT_MNTPOINT, "/", NULL, MS_MOVE, NULL) < 0) {
		printf("mount / MS_MOVE failed: %s\n", strerror(errno));
		return panic();
	}*/

	/* TODO this should use pivot_root */
	if (chroot(ROOT_MNTPOINT)) {
		printf("chroot failed: %s\n", strerror(errno));
		return panic();
	}
	if (chdir("/") < 0) {
		printf("chdir(\"/\") failed: %s\n", strerror(errno));
		return panic();
	}
	if (mount(NULL, "/dev", "devtmpfs", MS_NOEXEC|MS_NOSUID, NULL)) {
		printf("mount(/dev): %s\n", strerror(errno));
		return panic();
	}

	/* TODO check cmdline for init= ?*/
	if (execve(DEFAULT_INIT, nullp, nullp))
		printf("exec(%s): %s\n", DEFAULT_INIT, strerror(errno));

	return panic();
}
