#!/bin/sh

echo "***************************************************************"
echo "***          super basic init script version 0.1            ***"
echo "***************************************************************"

mount -vnt proc proc /proc
mount -vnt sysfs sysfs /sys

RW=no
if touch "/fswrtestfile" 2>/dev/null; then
	RW=yes
	rm -f /fswrtestfile
else
	echo "read-only filesystem."
fi

# check filesystem before remounting
# TODO test this with ext2
# TODO add --rescue option
if [ $RW = "no" ]; then
	echo "checking root filesystem"
	fsck -C -a /
	CHKRET=$?
	echo -n "filesystem check returned $CHKRET: "
	case "$CHKRET" in
	0)
		echo "no errors detected"
	;;
	1)
		echo "filesystem error(s) automatically corrected"
		sleep 3
	;;
	2)
		echo "reboot is required"
	;;
	*)
		echo "filesystem errors"
		echo "errors are uncorrected, rebooting may fix this."
		echo "if not, boot with --rescue appended to fix manually"
		echo "if ext2, \'e2fsck -v -y <root-partition>\' might help."
		echo "an incorrect /etc/fstab can also cause this error."
	;;
	esac
	if [ $CHKRET -ge 2 ]; then
		echo "press any key to reboot"
		read -n 1 anykey
		umount -var
		umount -vn -o remount,ro /
		echo "rebooting..."
		sleep 1
		reboot -f
	fi
else
	echo "filesystem was already mounted in r/w mode, this is unexpected."
	echo "your boot loader should be using ro / read-only option"
	echo "press any key to continue"
	read -n 1 anykey
fi


# remount r+w
echo "remounting root filesystem in read/write mode"
mount -wvn -o remount /
if [ $? -eq 0 ]; then
	rm -f /etc/mtab
	mount -vt proc proc /proc
	mount -vt sysfs sysfs /sys
else
	echo "failed remounting root filesystem in read/write mode"
	echo "press any key to continue"
	read -n 1 anykey
fi


# devices
# mount dev as tmpfs?
chown -R 0:0 /dev
chown 0:tty /dev/{ptmx,tty}
chown 0:0 /dev/console


# filesystems
# TODO mount stuff in fstab
mkdir /dev/pts
mount -vt devpts -o gid=5,mode=0620 devpts /dev/pts

#sysv shm

exit 0




