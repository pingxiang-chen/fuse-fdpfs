#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "inode.h"
#include "fdpfs.h"

#define block_size 4096
#define lba_shift 12

typedef struct superblock_t {
	char* data_bitmap;	// array of data block numbers that are available
	/* char** data_bitmaps; */
	char inode_bitmap[105];	// array of inode numbers that are available
} superblock;

void initialize_superblock(struct fdpfs_dev*, superblock*, unsigned int);
filetype* initialize_root_directory(superblock*);
