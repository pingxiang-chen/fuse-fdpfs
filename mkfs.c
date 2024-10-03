#define FUSE_USE_VERSION 34
#define FUSE_USE_VERSION 34

#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libnvme.h>
#include <errno.h>
#include <inttypes.h>
#include <endian.h>
#include <linux/io_uring.h>
#include <dirent.h>
#include <mntent.h>
#include <libgen.h>
#include <blkid/blkid.h>
#include <fuse.h>
#include <fuse_lowlevel.h>
#include <assert.h>
#include <sys/prctl.h>
#include <byteswap.h>
#include <endian.h>
#include <sys/types.h>
#include "fdpfs.h"
#include "io_uring.h"
#include "super.h"
#include "debug.h"
#include "uthash.h"

#ifdef FDPFS_DEBUG
#define FDPFS_DEBUG 1
#else
#define FDPFS_DEBUG 0
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <mqueue.h>

#define	FDP_DIR_DTYPE	2

int num_of_thread = 0;

bool initial_done = false;
bool write_done = false;

static struct fdpfs_dev dev;

char* blocks = NULL;

struct plmtid_pair {
	int plmtid;	/* key */
	int index;
	UT_hash_handle hh;	/* makes this structure hashable */
};

pthread_mutex_t lock;

struct plmtid_pair *plmtid_table = NULL;    /* important! initialize to NULL */

typedef struct {
	int data;
	const char *buffer;
	size_t size;
	off_t offset;
	enum fdpfs_ddir ddir;
	__u64 slba;
} message_t;

const struct debug_level debug_levels[] = {
	{ .name = "iouring",
	  .help = "IO uring logging",
	  .shift = FDPFS_IO_URING,
	},
	{ .name = "FUSE",
	  .help = "FUSE logging",
	  .shift = FDPFS_FUSE,
	},
	{ .name = "device",
	  .help = "FDP Device logging",
	  .shift = FDPFS_DEVICE,
	},
	{ .name = NULL, },
};

unsigned long fio_debug = 0;

#define MIN(a,b)	(a < b ? a : b)
#define BLKSIZE 4096

FILE *f_out = NULL;

typedef struct {
	int queue_id;
  	char name[20]; // Queue name for identification (optional)	
} queue_info_t;

queue_info_t * queue_infos;

/* This is x86 specific */
#define read_barrier()  __asm__ __volatile__("":::"memory")
#define write_barrier() __asm__ __volatile__("":::"memory")

/*
 * Command line options
 *
 * We can't set default values for the char* fields here because
 * fuse_opt_parse would attempt to free() them when the user specifies
 * different values on the command line.
 */
static struct options {
	const char *filename;
	const char *contents;
	const char * debug;
	int show_help;
} options;

#define OPTION(t, p) \
	{ t, offsetof(struct options, p), 1 }

static const struct fuse_opt option_spec[] = {
	OPTION("--name=%s", filename),
	OPTION("--contents=%s", contents),
	OPTION("--debug %s", debug),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

superblock spblock;
filetype* root;
filetype file_array[50];
struct nvme_fdp_ruh_status* ruh_status;
int counter;

void add_child(filetype * parent, filetype * child){
	(parent->num_children)++;
	
	parent->children = realloc(parent->children, 
			(parent->num_children)*sizeof(filetype*));
	
	(parent->children)[parent->num_children - 1] = child;
}

int find_free_inode(){
	for (int i = 2; i < 100; i++){
		if(spblock.inode_bitmap[i] == '0'){
			spblock.inode_bitmap[i] = '1';
			return i;
		}
	}

	return -1;
}

int find_free_db(int index){
	for (int i = 1; i < 100; i++){
		if(spblock.data_bitmap[i] == '0'){
			spblock.data_bitmap[i] = '1';
			return i;
		}
	}
	return -1;
}

filetype * filetype_from_path(char * path){
	char curr_folder[100];
	char *path_name = malloc(strlen(path) + 2);

	strcpy(path_name, path);

	filetype* curr_node = root;

	fflush(stdin);

	if(strcmp(path_name, "/") == 0)
		return curr_node;

	if(path_name[0] != '/'){
		printf("INCORRECT PATH\n");
		exit(1);
	}
	
	else{
		path_name++;
	}

	if(path_name[strlen(path_name)-1] == '/'){
		path_name[strlen(path_name)-1] = '\0';
	}
	
	char * index;
	int flag = 0;

	while(strlen(path_name) != 0){
		index = strchr(path_name, '/');

		if(index != NULL){
			strncpy(curr_folder, path_name, index - path_name);
			curr_folder[index-path_name] = '\0';
			flag = 0;
			for(int i = 0; i < curr_node -> num_children; i++){
				if(strcmp((curr_node->children)[i]->name, curr_folder) == 0){
					curr_node = (curr_node->children)[i];
					flag = 1;
					break;
				}
			}
			if(flag == 0)
				return NULL;
		}
		else{
			strcpy(curr_folder, path_name);
			flag = 0;
			for(int i = 0; i < curr_node -> num_children; i++){
				if(strcmp((curr_node -> children)[i] -> name, curr_folder) == 0){
					curr_node = (curr_node -> children)[i];
					return curr_node;
				}
			}
			return NULL;
		}
		path_name = index+1;
	}

	return NULL;
}

int find_index(unsigned int plmtid) {
    struct plmtid_pair *s;
	HASH_FIND_INT(plmtid_table, &plmtid, s);  /* s: output pointer */
	return s->index;
}


void tree_to_array(filetype* queue, int* front, int* rear, int* index){
	if(rear < front)
		return;
	if(*index > 30)
		return;

	filetype curr_node = queue[*front];
	*front += 1;
	file_array[*index] = curr_node;
	*index += 1;

	if(*index < 6){
		if(curr_node.valid){
			int i;
			for(i=0; i<curr_node.num_children; i++){
				if(*rear < *front)
					*rear = *front;
			queue[*rear] = *(curr_node.children[i]);
			*rear += 1;
			}
			while(i<5){
				filetype waste_node;
				waste_node.valid = 0;
				queue[*rear] = waste_node;
				*rear += 1;
				i++;
			}
		}
		else{
			int i = 0;
			while(i<5){
				filetype waste_node;
				waste_node.valid = 0;
				queue[*rear] = waste_node;
				*rear += 1;
				i++;
			}
		}
	}

	tree_to_array(queue, front, rear, index);
}

void fdpfs_close_dev(struct fdpfs_dev *dev){
	blkid_cache cache;
	int ret;
	// currently skip
	//ret = fsync(dev->fd);

	ret = blkid_get_cache(&cache, NULL);
	if (ret >= 0) {
		blkid_get_dev(cache, dev->path, BLKID_DEV_NORMAL);
		blkid_put_cache(cache);
	}
	blkid_send_uevent(dev->path, "change");
}

void print_fdp_info(struct fdpfs_dev *dev){
	dprint(FDPFS_DEVICE,	"Number of Reclaim Groups: %u\n", dev->nrg);
	dprint(FDPFS_DEVICE,	"Number of Reclaim Unit Handles: %u\n", dev->nruh);
	dprint(FDPFS_DEVICE,	"Number of Namespaces Supported: %u\n", dev->nnss);
	dprint(FDPFS_DEVICE,	"Reclaim Unit Nominal Size: %u\n", dev->runs);
	dprint(FDPFS_DEVICE,	"Estimated Reclaim Unit Time Limit: %u\n", dev->erutl);
	dprint(FDPFS_DEVICE,	"Reclaim Unit Handle List:\n");
	for (int j = 0; j < dev->nruh; j++) {
		struct nvme_fdp_ruh_desc *ruh = &dev->ruhs[j];
		dprint(FDPFS_DEVICE,"  [%d]: %s\n", j, ruh->ruht == NVME_FDP_RUHT_INITIALLY_ISOLATED ? "Initially Isolated" : "Persistently Isolated");
	}
}

void fdpfs_update_dev(struct fdpfs_dev *dev, struct nvme_fdp_config_desc* desc){
	/* Number of Reclaim Groups */
	dev->nrg = le32toh(desc->nrg);

	/* Number of Reclaim Unit Handles */
	dev->nruh = le16toh(desc->nruh);

	/* Number of Namespaces Supported */
	dev->nnss = le16toh(desc->nnss);

	/* Reclaim Unit Nominal Size */
	dev->runs = le64toh(desc->runs);

	/* Estimated Reclaim Unit Time Limit */
	dev->erutl = le32toh(desc->erutl);

	/* Reclaim Unit Handle List */
	dev->ruhs = desc->ruhs;

	print_fdp_info(dev);
}

int fdpfs_open_dev(struct fdpfs_dev *dev, bool check_overwrite){
	dev->name = basename(dev->path);

	/* Open device */
	dev->fd = open(dev->path, O_RDWR | O_EXCL);
	if (dev->fd < 0) {
		fprintf(stderr, "Open %s failed %d (%s)\n",
				dev->path,
				errno, strerror(errno));
		goto err;
	}

err:
	fdpfs_close_dev(dev);
	return 0;
}

/*
 * Read from completion queue.
 * In this function, we read completion events from the completion queue, get
 * the data buffer that will have the file data and print it to the console.
 * */

char* read_from_cq(struct ioring_data *ld) {
	struct io_cq_ring *cring = &ld->cq_ring;
    struct io_uring_cqe *cqe;
    unsigned head = 0;
	head = *cring->head;
	struct ioring_data* tmp;

    do {
		pid_t tid = gettid();
		read_barrier();
		/*
		 * Remember, this is a ring buffer. If head == tail, it means that the
		 * buffer is empty.
		 * */
		if (head == *cring->tail){
			break;
		}
		/* Get the entry */
		cqe = &cring->cqes[head & *ld->cq_ring.ring_mask];
		tmp = (struct ioring_data*)cqe->user_data;

		/* printf("read_from_cq, pid = %d, nsid = %d, tmp->dspec = %d\n", tid, tmp->nsid, tmp->dspec); */
		dprint(FDPFS_IO_URING, "read_from_cq, pid = %d, nsid = %d, tmp->dspec = %d\n", tid, tmp->nsid, tmp->dspec);
		if (cqe->res < 0)
			fprintf(stderr, "Error: %s\n", strerror(abs(cqe->res)));
		head++;
		
		/* for(int i=0; i<4096; i++){ */
		/* 	printf("tmp->orig_buffer[%d]: %c ", i, tmp->orig_buffer[i]); */ 
		/* } */
		/* printf("\n"); */

	} while (1);
    
	*cring->head = head;
	write_barrier();
	return tmp->orig_buffer;
}

int fdpfs_nvme_uring_cmd_prep(struct nvme_uring_cmd *cmd, struct ioring_data *ld, __u64 slba, __u32 nlb){
	memset(cmd, 0, sizeof(struct nvme_uring_cmd));
	
	switch (ld->ddir) {
    	case DDIR_READ:
			cmd->opcode = nvme_cmd_read;
			break;
		case DDIR_WRITE:
			cmd->opcode = nvme_cmd_write;
			break;
		default:
			return -ENOTSUP;
	}

	/* cdw10 and cdw11 represent starting lba */
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
	/* cdw12 represent number of lba's for read/write */
	cmd->cdw12 = nlb | (ld->dtype << 20);
	cmd->cdw13 = ld->dspec << 16;
	cmd->nsid = ld->nsid;
	cmd->addr = (__u64)(uintptr_t)ld->orig_buffer;
	/* cmd->data_len = ld->orig_buffer_size; */
	cmd->data_len = (nlb + 1)*block_size;	
	dprint(FDPFS_IO_URING, "fdpfs_nvme_uring_cmd_prep slba = %llu, nlb = %u, cmd->opcode = %u \n", 
			slba, nlb, cmd->opcode);
	dprint(FDPFS_IO_URING, "fdpfs_nvme_uring_cmd_prep ld->dspec	= %u, ld->dtype = %u\n", 
			ld->dspec, ld->dtype);
	dprint(FDPFS_IO_URING, "fdpfs_nvme_uring_cmd_prep cmd->addr = %llu cmd->data_len = %u \n", 
			cmd->addr, cmd->data_len);
	dprint(FDPFS_IO_URING, "fdpfs_nvme_uring_cmd_prep cmd->metadata = %llu cmd->metadata_len = %u \n", 
			cmd->metadata, cmd->metadata_len);

	/* printf("fdpfs_nvme_uring_cmd_prep = %zu\n", ld->orig_buffer_size); */	
	return 0;
}

int fdpfs_ioring_queue(struct ioring_data *ld){
	struct io_sq_ring *ring = &ld->sq_ring;
	unsigned tail, next_tail;
	int ret;
	tail = *ring->tail;
	next_tail = tail + 1;
	
	/* printf("fdpfs_ioring_queue top tail %u\n", tail); */
	/* ring->array[tail] = ld->index; */
	ring->array[tail & *ld->sq_ring.ring_mask] = ld->index;
	/* printf("fdpfs_ioring_queue bottom tail %u\n", tail); */
	
	/*
	 * Tell the kernel we have submitted events with the io_uring_enter() system
	 * call. We also pass in the IOURING_ENTER_GETEVENTS flag which causes the
	 * io_uring_enter() call to wait until min_complete events (the 3rd param)
	 * complete.
	 * */
	
	tail = next_tail;
	/* Update the tail so the kernel can see it. */
	if(*ring->tail != tail) {
		*ring->tail = tail;
	}
	
	ret = io_uring_enter(ld->ring_fd, 1,1, IORING_ENTER_GETEVENTS);
	
	if(ret < 0) {
		perror("io_uring_enter");
		return 1;
    }	
	
	/* printf("fdpfs_ioring_queue\n"); */
	return 0;
}

int submit_to_sq(struct fdpfs_dev *dev, struct ioring_data *ld, message_t msg){
	unsigned index = 0;
	struct nvme_uring_cmd *cmd;
	struct io_uring_sqe *sqe;
	sqe = &ld->sqes[(index) << 1];
	sqe->fd = dev->fd;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->cmd_op = NVME_URING_CMD_IO;
	ld->dspec = msg.data;
	__u64 slba;
	__u32 nlb;

	dprint(FDPFS_IO_URING, "submit_to_sq\n");

	if(msg.size <=0)
		return -EIO;

#if FDPFS_DEBUG
	dprint(FDPFS_IO_URING, "msg.ddir = %d\n", msg.ddir);
	dprint(FDPFS_IO_URING, "msg.size = %zu\n", msg.size); 
	dprint(FDPFS_IO_URING, "msg.offset = %ld\n", msg.offset);
	dprint(FDPFS_IO_URING, "msg.slba = %lld\n", msg.slba);
	dprint(FDPFS_IO_URING, "dev->fd = %d\n", dev->fd);
	dprint(FDPFS_IO_URING, "dev->nsid = %d\n", dev->nsid);
	dprint(FDPFS_IO_URING, "ld->ring_fd = %d\n", ld->ring_fd);
	dprint(FDPFS_IO_URING, "sqe->opcode = %u\n", IORING_OP_URING_CMD);
	dprint(FDPFS_IO_URING, "sqe->cmd_op = %lu\n", NVME_URING_CMD_IO);
#endif
	sqe->user_data = (unsigned long) ld;
	cmd = (struct nvme_uring_cmd *)sqe->cmd;
	ld->nsid = dev->nsid;
	ld->index = index;
	slba = msg.slba;
	nlb = (msg.size % block_size == 0) ?  msg.size / block_size -1 : msg.size / block_size;
	/* ld->orig_buffer_size = (nlb + 1) * block_size; */
	/* printf("submit_to_sq orig_buffer_size = %zu\n", ld->orig_buffer_size); */
	/* ld->orig_buffer = malloc(ld->orig_buffer_size); */
	
	switch (msg.ddir) {
    	case DDIR_READ:
			ld->ddir = DDIR_READ;
			ld->dtype = 0;
			ld->dspec = 0;
			/* nlb += 1; */
			break;
    	case DDIR_WRITE:
        	ld->ddir = DDIR_WRITE;
			ld->orig_buffer = (char*)msg.buffer;
			ld->dtype = FDP_DIR_DTYPE;
			break;
    	default:
        	return -ENOTSUP;
    }
	
	dprint(FDPFS_IO_URING, "slba = %llu, nlb = %u\n", slba, nlb);
	
	return fdpfs_nvme_uring_cmd_prep(cmd, ld, slba, nlb);
}

void *receiver(void *arg){
	message_t msg;
	struct ioring_data *ld;
	ld = malloc(sizeof(*ld));
	queue_info_t *info = (queue_info_t *)arg;
	
	pid_t tid = gettid();

	dprint(FDPFS_IO_URING, "Initilize Queue id: %d, name: %s, pid: %d\n", 
			info->queue_id, info->name, tid);
    
	if(!ld){
		perror("malloc");
		return NULL;
    }

	memset(ld, 0, sizeof(*ld));

	if(fdpfs_ioring_queue_init(ld))
		perror("fdpfs_ioring_queue_init_failed\n");	

	dprint(FDPFS_IO_URING, "io_uring_queue_init success\n");

	ld->orig_buffer_size = (4 + 1) * block_size;
	printf("malloc orig_buffer orig_buffer_size = %zu\n", ld->orig_buffer_size);
	ld->orig_buffer = malloc(ld->orig_buffer_size);
	

	while (1) {
		int ret = mq_receive(info->queue_id, (char *) &msg, sizeof(message_t), NULL);
		if (ret == -1) {
			perror("mq_receive");
			exit(1);
		}
		/* printf("receive the message pid = %d, ddir = %d\n", tid, msg.ddir); */ 
		
		/* pthread_mutex_lock(&lock); */	
		
		/* if(msg.ddir==DDIR_READ){ */
		/* 	blocks = NULL; */
		/* 	if(blocks == NULL) */
		/* 		printf("initialize blocks to null\n"); */
		/* } */
		submit_to_sq(&dev, ld, msg);
		fdpfs_ioring_queue(ld);
		blocks = read_from_cq(ld);
		
		/* if(msg.ddir==DDIR_READ) */
		/* 	printf("finish job pid = %d, DDIR_READ\n", tid); */
		/* if(msg.ddir==DDIR_WRITE){ */
		/* 	write_done = true; */
		/* } */
		/* while(blocks == NULL) */
		/* 	printf("blocks is NULL\n!!"); */
		
		/* pthread_mutex_unlock(&lock); */ 
		
		/* for(int i=0; i<4096; i++){ */
		/* 	printf("blocks[%d]: %c ", i, blocks[i]); */ 
		/* } */
		/* printf("\n"); */

		if(msg.ddir==DDIR_WRITE) 
			write_done = true;
		
		dprint(FDPFS_IO_URING, "Queue id: %d, name: %s processing message: %d, msg.ddir=%d\n", 
				info->queue_id,info->name, msg.data, msg.ddir);
	}

	num_of_thread++;
	return NULL;
}

static int do_getattr(const char *path, struct stat *statit, struct fuse_file_info* fi){
	char *pathname;
	pathname=(char *)malloc(strlen(path) + 2);

	strcpy(pathname, path);

	filetype * file_node = filetype_from_path(pathname);
	if(file_node == NULL)
		return -ENOENT;

	statit->st_uid = file_node->user_id; 
	statit->st_gid = file_node->group_id; 
	statit->st_atime = file_node->a_time; 
	statit->st_mtime = file_node->m_time; 
	statit->st_ctime = file_node->c_time;
	statit->st_mode = file_node->permissions;
	statit->st_nlink = file_node->num_links + file_node -> num_children;
	statit->st_size = file_node->size;
	statit->st_blocks = file_node->blocks;

	return 0;
}

int do_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, 
		struct fuse_file_info *fi, enum fuse_readdir_flags){
	
	filler(buffer, ".", NULL, 0, 0);
	filler(buffer, "..", NULL,0, 0);

	char* pathname = malloc(strlen(path)+2);
	strcpy(pathname, path);

	filetype* dir_node = filetype_from_path(pathname);

	if(dir_node == NULL){
		return -ENOENT;
	}
	else{
		dir_node->a_time=time(NULL);
		for(int i = 0; i < dir_node->num_children; i++){
			filler(buffer, dir_node->children[i]->name, NULL, 0, 0);
		}
	}
	return 0;
}

unsigned int get_plmtid_from_path(const char* path){
	char* pathname = malloc(strlen(path)+2);
	char* token = NULL;
	unsigned int plmtid = 0;
	
	strcpy(pathname, path);
	token = strtok(pathname, "/");
	sscanf(token,"p%u",&plmtid);	
	free(pathname);	

	return plmtid;
}


int do_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
	char* pathname = malloc(sizeof(path)+1);
	strcpy(pathname, path);
	filetype* file = filetype_from_path(pathname);
	int pos, blk;
	uint32_t n;
	int plmtid = get_plmtid_from_path(path);
	int total_bytes = 0;
	message_t msg;
	int idx = 0;
	int which_queue = 0;
	
	if(file == NULL)
		return -ENOENT;
	
	dprint(FDPFS_FUSE, "do_read: %s, size: %zu, offset: %ld\n", path, size, offset);
	
	
	size = MIN(size, file->size - offset);
	
	for(pos = offset; pos < offset + size;){
		/* printf("pos = %d, file->size = %ld, size = %lu, total_bytes = %u\n", pos, file->size, size, total_bytes); */
		n = MIN(block_size - pos % block_size, offset + size - pos);
		blk = pos/block_size;
		msg.data = plmtid; // Set data for the message
		msg.buffer = NULL; 
		msg.offset = 0;
		msg.ddir = DDIR_READ;
		msg.slba = file->datablocks[blk];
		msg.size = n;
		idx = find_index(plmtid);
		which_queue = idx % num_of_thread;
		blocks = NULL;
		
		int ret = mq_send(queue_infos[which_queue].queue_id, (const char *) &msg, sizeof(message_t), 0); // Send message
		
		if(ret == -1){
			return -EIO;
		}

		while(blocks==NULL){
		
		}
		
		for(int i=0; i<n; i++){
			buf[i] = blocks[i];
			/* printf("%c\n", blocks[i]); */
		}
		
		pos += n;
		buf += n;
		total_bytes += n;
	}

	return total_bytes;
}

int get_file_level(const char* path){
	char* pathname = malloc(strlen(path)+2);
	char* token = NULL;
	int level = 0;
	strcpy(pathname, path);
	token = strtok(pathname, "/");
	
	// loop through the string to extract all other tokens
	while(token != NULL){
		token = strtok(NULL, "/");
		level++;
	}
	
	free(pathname);	
	return level;
}

static int do_mkdir(const char *path, mode_t mode) {
	int index = find_free_inode();
	int level = 0;

	if(index==-1)
		return -ENOSPC;
	
	level = get_file_level(path);
	
	if(initial_done && level <= 1)
		return -EROFS;

	filetype* new_folder = malloc(sizeof(filetype));

	char* pathname = malloc(strlen(path)+2);
	strcpy(pathname, path);

	char* rindex = strrchr(pathname, '/');

	strcpy(new_folder->name, rindex+1);
	strcpy(new_folder->path, pathname);
	
	*rindex = '\0';
	
	if(strlen(pathname) == 0)
		strcpy(pathname, "/");

	new_folder->children = NULL;
	new_folder->num_children = 0;
	new_folder->parent = filetype_from_path(pathname);
	new_folder->num_links = 2;
	new_folder->valid = 1;
	
	strcpy(new_folder->test, "test");

	if(new_folder->parent == NULL)
		return -ENOENT;

	add_child(new_folder->parent, new_folder);
	strcpy(new_folder->type, "directory");

	new_folder->c_time = time(NULL);
	new_folder->a_time = time(NULL);
	new_folder->m_time = time(NULL);
	new_folder->b_time = time(NULL);
	new_folder->permissions = S_IFDIR | 0777;
	new_folder->size = 0;
	new_folder->group_id = getgid();
	new_folder->user_id = getuid();

	new_folder->number = index;
	new_folder->blocks = 0;
	
	return 0;
}


int do_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	int plmt_id = 0;
	char * pathname = malloc(sizeof(path)+1);
	int pos, blk;
	uint32_t n;
	message_t msg;
	strcpy(pathname, path);
	pid_t tid = gettid();
	filetype * file = filetype_from_path(pathname);
	int idx = find_index(plmt_id);
	int which_queue = idx % num_of_thread;
		
	dprint(FDPFS_FUSE, "pid = %d, do_write: %s, size: %zu, offset: %ld\n", tid, path, size, offset);
	counter += 1;

	if(file == NULL)
		return -ENOENT;
	
	plmt_id = get_plmtid_from_path(path);
	
	/* printf("\n Job %d has started, counter=%d\n", tid, counter); */ 
	
	for(pos = offset; pos < offset + size;){
		// read one block out
		n = MIN(block_size - pos % block_size, offset + size - pos);
		blocks = NULL;
		/* printf("pid = %d, make blocks to null!\n", tid); */
		blk = pos/block_size;
		msg.data = plmt_id; // Set data for the message
		msg.buffer = NULL; 
		msg.offset = 0;
		msg.ddir = DDIR_READ;
		msg.slba = file->datablocks[blk];
		msg.size = n;
		idx = find_index(plmt_id);
		which_queue = idx % num_of_thread;
		
		int ret = mq_send(queue_infos[which_queue].queue_id, (const char *) &msg, sizeof(message_t), 0); // Send message
		
		if(ret == -1){
			return -EIO;
		}

		while(blocks==NULL){
			/* printf("wait for blocks to come!!!\n"); */
		}

		/* printf("read block %d\n", file->datablocks[blk]); */

		/* for(int i=0; i<16; i++){ */
		/* 	printf("blocks[%d]: %c \n", i, blocks[i]); */
		/* } */	
		
		/* printf("\n"); */

		blk = pos/block_size;
	
		if(pos + n > file->size)
			file->size = pos + n; 	// update file size accordingly.
		
		msg.data = plmt_id; // Set data for the message
		msg.size = n;
		msg.offset = pos;
		msg.ddir = DDIR_WRITE;
		msg.slba = file->datablocks[blk];
	
		/* if(blocks==NULL) */
		/* 	printf("blocks is null!!!!\n"); */

		for(int i=0; i<n; i++){
			blocks[pos % block_size + i] = buf[i];
			/* printf("blocks[%d] = %c\n", pos % block_size + i, blocks[pos % block_size + i]); */
			/* printf("write buf[%d] = %c\n", i, buf[i]); */
		}
		
		/* printf("done block memory write\n"); */

		msg.buffer = blocks; 
		
		/* printf("file->datablocks[%d] = %d\n", blk, file->datablocks[blk]); */
		
		write_done = false;
		ret = mq_send(queue_infos[which_queue].queue_id, (const char *) &msg, sizeof(message_t), 0); // Send message
		
		if(ret == -1){
			perror("mq_send failure at do_write");
			return -EIO;
		}
		
		while(!write_done){
			/* printf("write not done\n"); */
		}
		/* printf("send to device \n"); */

		pos += n; // update pos.
		buf += n;
	}	
	
	/* pthread_mutex_unlock(&lock); */ 
    /* printf("\n Job %d has finished\n", tid); */ 
	return size;
}

void add_to_plmtid_table(int plmtid, int index) {
	struct plmtid_pair *s;
	s = malloc(sizeof *s);
	s->plmtid = plmtid;
	s->index =  index;
	HASH_ADD_INT(plmtid_table, plmtid, s);  /* id: name of key field */
}

static void *fdpfs_init(struct fuse_conn_info *conn,
                        struct fuse_config *cfg)
{
	
	(void) conn;
	cfg->kernel_cache = 1;
	cfg->direct_io = 1;
	
	unsigned int num_of_blocks = le64toh(dev.runs) / block_size;
	num_of_blocks = dev.maxPIDIdx_ * num_of_blocks;

	dprint(FDPFS_DEVICE, "num_of_blocks = %u\n", num_of_blocks);
	initialize_superblock(&dev ,&spblock, num_of_blocks);
	root = initialize_root_directory(&spblock);
	
	char buffer[50];
	
	for(uint16_t i=0; i<dev.maxPIDIdx_; i++){
		sprintf(buffer, "/p%u", dev.pIDs[i].pid);
		add_to_plmtid_table((int)dev.pIDs[i].pid, i);	
		do_mkdir(buffer, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}
	
	initial_done = true;
	return NULL;
}

int do_create(const char * path, mode_t mode, struct fuse_file_info *fi) {
	int level = 0; 
	int index = -1;
	unsigned int plmtid;
	
	level = get_file_level(path);
	
	if(level<=1)
		return -EROFS;

	index = find_free_inode();
	plmtid = get_plmtid_from_path(path);

	if(index==-1)
		return -ENOSPC;

	filetype * new_file = malloc(sizeof(filetype));

	char * pathname = malloc(strlen(path)+2);
	strcpy(pathname, path);

	char * rindex = strrchr(pathname, '/');

	strcpy(new_file -> name, rindex+1);
	strcpy(new_file -> path, pathname);

	*rindex = '\0';

	if(strlen(pathname) == 0)
		strcpy(pathname, "/");

	new_file -> children = NULL;
	new_file -> num_children = 0;
	new_file -> parent = filetype_from_path(pathname);
	new_file -> num_links = 0;
	new_file -> valid = 1;

	if(new_file -> parent == NULL)
		return -ENOENT;

	add_child(new_file->parent, new_file);

	strcpy(new_file -> type, "file");

	new_file->c_time = time(NULL);
	new_file->a_time = time(NULL);
	new_file->m_time = time(NULL);
	new_file->b_time = time(NULL);
	new_file->permissions = S_IFREG | 0777;
	new_file->size = 0;
	new_file->group_id = getgid();
	new_file->user_id = getuid();
	new_file->number = index;

	int free_block = 0;
	int bitmaps_idx = find_index(plmtid);

	for(int i = 0; i < 16; i++){
		free_block = find_free_db(bitmaps_idx);
		
		if(free_block == -1)
			return -ENOSPC;
		
		(new_file->datablocks)[i] = free_block;
	}
	
	new_file->blocks = 0;
	
	return 0;
}

int do_open(const char *path, struct fuse_file_info *fi) {
	char * pathname = malloc(sizeof(path)+1);
	strcpy(pathname, path);
	/* filetype* file = filetype_from_path(pathname); */
	return 0;
}

static struct fuse_operations operations = {
	.init		=	fdpfs_init,
	.getattr	=	do_getattr,
	.readdir	=	do_readdir,
	.read		=	do_read,
	.mkdir		=	do_mkdir,
	.write		=	do_write,
	.create		= 	do_create,
	.open		=	do_open,
};
 
static void show_help(const char *progname)
{
	printf("usage: %s [options] <mountpoint>\n\n", progname);
	printf("File-system specific options:\n"
			"    --name=<s>          Name of the \"hello\" file\n"
			"                        (default: \"hello\")\n"
			"    --contents=<s>      Contents \"hello\" file\n"
			"                        (default \"Hello, World!\\n\")\n"
			"\n");
}

void fdpfs_update_dev_ruh_status(struct fdpfs_dev *dev, struct nvme_fdp_ruh_status* status){
	/* uint16_t nruhsd = le16toh(status->nruhsd); */	
	
	dev->maxPIDIdx_ = ruh_status->nruhsd - 1;

	dev->pIDs = (struct placementIDs_*)malloc(dev->maxPIDIdx_*
			sizeof(struct placementIDs_));
	
	for(uint16_t i=0; i<=dev->maxPIDIdx_; i++){
		struct nvme_fdp_ruh_status_desc *ruhs = &status->ruhss[i];
		dev->pIDs[i].pid = le16toh(ruhs->pid);
		dev->pIDs[i].ruhid = le16toh(ruhs->ruhid);
	}
}

static int nvme_passthru_identify(int fd, __u32 nsid, enum nvme_identify_cns cns,
             enum nvme_csi csi, void *data)
{   
	struct nvme_passthru_cmd cmd = {
		.opcode		=	nvme_admin_identify,
		.nsid		=	nsid,
		.addr		= 	(__u64)(uintptr_t)data,
		.data_len	=	NVME_IDENTIFY_DATA_SIZE,
		.cdw10		= 	cns,
		.cdw11		= 	csi << NVME_IDENTIFY_CSI_SHIFT,
		.timeout_ms	= 	NVME_DEFAULT_IOCTL_TIMEOUT,
	};

	return ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
}       

int main(int argc, char *argv[])
{
	int ret = 0;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct nvme_fdp_config_log hdr;
	struct nvme_fdp_config_desc* desc;
	struct nvme_fdp_config_log *conf;
	struct nvme_id_ctrl ctrl;	
	/* pthread_t threads[8]; */
	
	/* struct nvme_nvm_id_ns nvm_ns; */
	/* struct ioring_data *ld; */
	/* struct nvme_id_ns ns; */ 
	
	f_out = stdout;	
	
	void *log = NULL;
	int err;
	struct mq_attr attributes;
	attributes.mq_flags = 0; // No specific flags
	attributes.mq_maxmsg = 16; // Max number of messages in queue
	attributes.mq_curmsgs = 0; // Current number of messages (always 0 at creation)
	attributes.mq_msgsize = sizeof(message_t);
	
	struct config {
		__u16	egid;
		__u32	namespace_id;
		char	*output_format;
		bool	human_readable;
		bool	raw_binary;
	};  

	struct config cfg = { 
		.egid			=	0,
		.output_format	=	"normal",
		.raw_binary		=	false,
	}; 
	
	/* 
	 * Set defaults -- we have to use strdup so that
	 * fuse_opt_parse can free the defaults if other
	 * values are specified
	 * */
	options.filename = strdup("/dev/ng1n1");
	options.contents = strdup("1");
	cfg.egid = (__u16)atoi(options.contents); 

	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL)==-1){
		return 1;
	}
	
	if(options.debug){
		char *ch;
		char *debug = (char*)options.debug;
		const struct debug_level *dl;
		int i;
		ch = strtok(debug, " ");
		while (ch != NULL) {
			int found = 0;
			for (i = 0; debug_levels[i].name; i++) {
            	dl = &debug_levels[i];
            	found = !strncmp(ch, dl->name, strlen(dl->name));
            	if (found){
					fio_debug |= (1UL << dl->shift);
					break;
				}
			}
    		ch = strtok(NULL, " ");
  		}
	}

	
	/*
	 * When --help is specified, first print our own file-system
	 * specific help text, then signal fuse_main to show
	 * additional help (by adding `--help` to the options again)
	 * without usage: line (by setting argv[0] to the empty
	 * string) 
	 * */
	if (options.show_help) {
		show_help(argv[0]);
		assert(fuse_opt_add_arg(&args, "--help") == 0);
		args.argv[0][0] = '\0';
	}

	int fd = open(options.filename, O_RDONLY);
		
	if (fd == -1) {
		perror("open():");
		return EXIT_FAILURE;
	}	
	dev.fd = fd;
	
	dprint(FDPFS_FUSE, "open fd %d\n", fd);
	
	int namespace_id = ioctl(fd, NVME_IOCTL_ID);
    
	if (namespace_id < 0) {
		perror("failed to fetch namespace-id\n");
		goto fclose;
	}   
	
	dev.nsid = namespace_id;
	
	err = nvme_passthru_identify(fd, 0, NVME_IDENTIFY_CNS_CTRL, NVME_CSI_NVM, &ctrl);
    
	if (err) {
		printf("%s: failed to fetch identify ctrl\n", options.filename);
		goto fclose;
	}

	struct stat stat_buf;
	ret = fstat(fd, &stat_buf);
	err = nvme_get_log_fdp_configurations(fd, cfg.egid, 0, sizeof(hdr), &hdr);
	
 	if(err){
		goto fclose;
	}

	log = malloc(hdr.size);
    
	if (!log) {
		err = -ENOMEM;
		goto fclose;
	}

	err = nvme_get_log_fdp_configurations(fd, cfg.egid, 0, hdr.size, log);
	
	if(err){
		goto fclose;
	}

	conf = log;
	desc = conf->configs;
	
	// TODO: need to check whats the purpose of n in here.
	// uint16_t n;
	// n = le16toh(conf->n) + 1;
	fdpfs_update_dev(&dev, desc);
	
	
	if (!cfg.namespace_id) {
		err = nvme_get_nsid(fd, &cfg.namespace_id);
		if (err < 0) {
			perror("get-namespace-id");
			goto fclose;
		}
	}
	
	struct nvme_fdp_ruh_status hdr2;
	size_t len;
	void *buf = NULL;
	err = nvme_fdp_reclaim_unit_handle_status(fd, cfg.namespace_id, sizeof(hdr2), &hdr2);

	if (err) {
		perror("error\n");
		goto fclose;
	}
	len = sizeof(struct nvme_fdp_ruh_status) + 
		le16toh(hdr2.nruhsd) * sizeof(struct nvme_fdp_ruh_status_desc);
	
	buf = malloc(len);
    
	if (!buf) {
		err = -ENOMEM;
		goto fclose;
	}
	
	err = nvme_fdp_reclaim_unit_handle_status(fd, cfg.namespace_id, len, buf);

	if (err) {
		goto fclose;
	}

	ruh_status = (struct nvme_fdp_ruh_status *)buf;
	
	fdpfs_update_dev_ruh_status(&dev, ruh_status);
	
	num_of_thread = dev.nruh;

	queue_infos = (queue_info_t*)malloc(num_of_thread * sizeof(queue_info_t));

	pthread_t threads[8];
	
	// Create message queues
	for (int i = 0; i < num_of_thread; i++) {
		sprintf(queue_infos[i].name, "/queue_%d", i);
	}
	
	for (int i = 0; i < num_of_thread; i++) {
		queue_infos[i].queue_id = mq_open(queue_infos[i].name, O_CREAT | O_RDWR, 0666, &attributes);
		if (queue_infos[i].queue_id == (mqd_t)-1){
			perror("mq_open");
			exit(1);
		}
	}

	for (int i = 0; i < num_of_thread; i++) {
		if (pthread_create(&threads[i], NULL, receiver, &queue_infos[i]) != 0) {
			perror("pthread_create");
			exit(1);
		}
	}
	
	if(pthread_mutex_init(&lock, NULL) != 0) { 
		printf("\n mutex init has failed\n"); 
		exit(1); 
	} 

	ret = fuse_main(args.argc, args.argv, &operations, NULL);

fclose:
 	// Wait for all consumer threads to finish
	dprint(FDPFS_FUSE, "fclose\n");
	
	for (int i = 0; i < num_of_thread; i++) {
    	if (pthread_join(threads[i], NULL) != 0) {
			perror("pthread_join");
			exit(1);
		}
	}
	for (int i = 0; i < num_of_thread; i++) {
		mq_close(queue_infos[i].queue_id);
		mq_unlink(queue_infos[i].name); // Remove the queue from the system
  	}

	pthread_mutex_destroy(&lock);
#if FDPFS_DEBUG
	dprint(FDPFS_FUSE, "Close file\n");
#endif
	close(fd);
	fuse_opt_free_args(&args);
	return ret;
}
