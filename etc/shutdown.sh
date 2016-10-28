#!/bin/sh
echo "---------------------------------"
echo "    the basic shutdown script    " 
echo "---------------------------------"
echo "swapoff"
swapoff -a
sync
sleep 2
echo "unmounting filesystems"
umount -v -a -r -t no,procfs,sysfs
mount -v -n -o remount,ro /
echo "synchronizing storage devices"
sleep 6 
sync
echo "fin."
sleep 2 
exit 0
