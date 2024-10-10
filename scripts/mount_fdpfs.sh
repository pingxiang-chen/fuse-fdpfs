#!/bin/bash

BINARY="../mkfs.fdpfs"
MOUNT_POINT="./fuse_mount"

if [ "$EUID" -ne 0 ]
	then echo "Please run as root"
	exit
fi

if [ ! -d $MOUNT_POINT ]; then
	mkdir $MOUNT_POINT	
fi

if [ "$#" -ne 1 ]; then
	echo "./mount_fdpfs [foreground/background mode/debug mode]"
	echo -e "\t ./mount_fdpfs 1 -> foreground mode"
	echo -e "\t ./mount_fdpfs 2 -> background mode" 
	echo -e "\t ./mount_fdpfs 3 -> debug mode" 
	exit
fi

case "$1" in
	1)
		echo "run fdpfs in foreground mode"
		$BINARY -d $MOUNT_POINT
	;;

	2)
		echo "run fdpfs in background mode"
		$BINARY -f $MOUNT_POINT
	;;  

	3)
		echo "run fdpfs in background mode"
		$BINARY -d $MOUNT_POINT --debug "iouring FUSE device"
	;;

	*)
		echo "Please use valid argument"	
	;;  
esac

# $BINARY -f $MOUNT_POINT 
# $BINARY -d $MOUNT_POINT 
# $BINARY -d $MOUNT_POINT --debug "iouring FUSE device" 
