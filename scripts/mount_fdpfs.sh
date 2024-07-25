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


$BINARY -d $MOUNT_POINT
