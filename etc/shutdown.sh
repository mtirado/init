#!/bin/sh
echo "---------------------------------"
echo "    the basic shutdown script    "
echo "---------------------------------"
echo "swapoff"
swapoff -a
sync
sleep 2
echo "unmounting filesystems"
umount -v -a -r
mount -v -n -o remount,ro /
echo "synchronizing storage devices"
sync
sleep 6
echo "fin."
sleep 2
exit 0
