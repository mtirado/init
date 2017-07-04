#!/bin/sh

NETDEV=eth0
# defaults for qemu
IPADDR=10.0.2.15/24
GATEWAY=10.0.2.2

echo "***************************************************************"
echo "***          super basic init script version 0.2            ***"
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
		#echo "if not, boot with --rescue appended to fix manually"
		echo "if ext2, \'e2fsck -v -y <root-partition>\' might help."
		echo "an incorrect /etc/fstab can also cause this error."
	;;
	esac
	if [ $CHKRET -ge 2 ]; then
		umount -var
		umount -vn -o remount,ro /
		echo "press return key to reboot"
		read anykey
		shutdown -Zr
	fi
else
	echo "filesystem was already mounted in r/w mode, this is unexpected."
	echo "your boot loader should be using ro / read-only option"
#	echo "press any key to continue"
#	read -n 1 anykey
fi


# remount r+w
mount -wvn -o remount /
if [ $? -eq 0 ]; then
	rm -f /etc/mtab
	echo "remounted rootfs with +rw"
else
	echo "failed remounting root filesystem in read/write mode"
#	echo "press any key to continue"
#	read -n 1 anykey
fi


# devices
# mount dev as tmpfs?
chown -R 0:0 /dev
chown 0:0 /dev/{ptmx,tty}
chown 0:0 /dev/console

mkdir -p /dev/pts
mkdir -p /home
mkdir -p /opt

mount -wv -o remount /
mount -v -a
if [ $? -ne 0 ]; then
	echo "fstab mount issues <-------------"
fi

#sysv shm

#setup network
echo "setting ip address: $IPADDR"
ip addr add $IPADDR dev eth0
echo "bringing up $NETDEV"
ip link set dev $NETDEV up
echo "setting gateway: $GATEWAY"
ip route add default via $GATEWAY
/root/firewall.sh
if [ $? -ne 0 ]; then
	echo "firewall script failed! <-------------"
	sleep 1
fi

#restore alsa settings
alsactl restore

exit 0




