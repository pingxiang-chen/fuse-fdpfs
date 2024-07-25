#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "inode.h"

#define block_size 4096

typedef struct superblock_t {
	char datablocks[block_size*100];		// total number of data blocks
	char* data_bitmap;      			// array of data block numbers that are available
	char inode_bitmap[105];   				// array of inode numbers that are available
} superblock;

void initialize_superblock(superblock*, unsigned int);
filetype* initialize_root_directory(superblock*);
