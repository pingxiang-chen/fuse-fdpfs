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
#include "fdpfs.h"
#include "io_uring.h"
#include "super.h"

#ifdef FDPFS_DEBUG
#define FDPFS_DEBUG 1
#else
#define FDPFS_DEBUG 0
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <mqueue.h>

int num_of_thread = 0;

static struct fdpfs_dev dev;

char* blocks;

typedef struct {
	int data;
	const char *buffer;
	size_t size;
	off_t offset;
	enum fdpfs_ddir ddir;
	__u64 slba;
} message_t;

#define NUM_QUEUES 2  // Number of message queues to create
#define MIN(a,b)	(a < b ? a : b)
#define BLKSIZE 4096

typedef struct {
	int queue_id;
  	char name[20]; // Queue name for identification (optional)	
} queue_info_t;

queue_info_t queue_infos[NUM_QUEUES];

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
	int show_help;
} options;

#define OPTION(t, p) \
	{ t, offsetof(struct options, p), 1 }

static const struct fuse_opt option_spec[] = {
	OPTION("--name=%s", filename),
	OPTION("--contents=%s", contents),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

superblock spblock;
filetype* root;
filetype file_array[50];
struct nvme_fdp_ruh_status* ruh_status;

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
		}
			return i;
	}

	return -1;
}

int find_free_db(){
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
	char * path_name = malloc(strlen(path) + 2);

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

void read_block(filetype* file, int blk, uint32_t n){
	blocks = NULL;
	int plmt_id = 0;
	message_t msg;

	printf("read_block: blk = %d, n = %d\n", blk, n);

	msg.data = plmt_id; // Set data for the message
	msg.buffer = NULL; 
	msg.size = n;
	msg.offset = 0;
	msg.ddir = DDIR_READ;
	msg.slba = file->datablocks[blk];

	int ret = mq_send(queue_infos[plmt_id].queue_id, (const char *) &msg, sizeof(message_t), 0); // Send message

	if(ret == -1){
		perror("mq_send failure at read_block");
		return;
	}

	while(blocks==NULL){
	}
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

void fdpfs_close_dev(struct fdpfs_dev *dev)
{
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

void print_fdp_info(struct fdpfs_dev *dev)
{
	printf("Number of Reclaim Groups: %u\n", dev->nrg);
	printf("Number of Reclaim Unit Handles: %u\n", dev->nruh);
	printf("Number of Namespaces Supported: %u\n", dev->nnss);
	printf("Reclaim Unit Nominal Size: %u\n", dev->runs);
	printf("Estimated Reclaim Unit Time Limit: %u\n", dev->erutl);
	printf("Reclaim Unit Handle List:\n");
	for (int j = 0; j < dev->nruh; j++) {
		struct nvme_fdp_ruh_desc *ruh = &dev->ruhs[j];
		printf("  [%d]: %s\n", j, ruh->ruht == NVME_FDP_RUHT_INITIALLY_ISOLATED ? "Initially Isolated" : "Persistently Isolated");
	}
}

void fdpfs_update_dev(struct fdpfs_dev *dev, struct nvme_fdp_config_desc* desc)
{
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
}

int fdpfs_open_dev(struct fdpfs_dev *dev, bool check_overwrite)
{
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
		tmp = (struct ioring_data*) cqe->user_data;

#if FDPFS_DEBUG	
		printf("read_from_cq, nsid = %d\n", tmp->nsid);
		if(!tmp->orig_buffer)
			printf("no data\n");
		else{
			printf("read_from_cq, orig_buffer = %s\n", tmp->orig_buffer);
		}
#endif		
		if (cqe->res < 0)
			fprintf(stderr, "Error: %s\n", strerror(abs(cqe->res)));
		head++;
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
#if FDPFS_DEBUG	
	printf("fdpfs_nvme_uring_cmd_prep slba = %llu, nlb = %u, cmd->opcode = %u \n", slba, nlb, cmd->opcode);
	printf("fdpfs_nvme_uring_cmd_prep ld->dspec	= %u, ld->dtype = %u\n", ld->dspec, ld->dtype);
#endif 
	/* cdw10 and cdw11 represent starting lba */
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
    /* cdw12 represent number of lba's for read/write */
	cmd->cdw12 = nlb | (ld->dtype << 20);
	cmd->cdw13 = ld->dspec << 16;
	cmd->nsid = ld->nsid;
	cmd->addr = (__u64)(uintptr_t)ld->orig_buffer;
	cmd->data_len = ld->orig_buffer_size;
#if FDPFS_DEBUG
	printf("fdpfs_nvme_uring_cmd_prep cmd->addr = %llu cmd->data_len = %u \n", cmd->addr, cmd->data_len);
	printf("fdpfs_nvme_uring_cmd_prep cmd->metadata = %llu cmd->metadata_len = %u \n", cmd->metadata, cmd->metadata_len);
#endif
	return 0;
}

int fdpfs_ioring_queue(struct ioring_data *ld){
	struct io_sq_ring *ring = &ld->sq_ring;
	unsigned tail, next_tail;
	int ret;
	tail = *ring->tail;
	next_tail = tail + 1;
#if FDPFS_DEBUG
	__u64 slba;
	struct io_uring_sqe *sqe;
	struct nvme_uring_cmd *cmd;
	sqe = &ld->sqes[(ld->index) << 1];
	cmd = (struct nvme_uring_cmd *)sqe->cmd;
	slba = cmd->cdw10 & 0xffffffff;
	printf("fdpfs_ioring_queue slba = %llu index = %u\n", slba, ld->index);
	printf("fdpfs_ioring_queue cmd->opcode = %u \n", cmd->opcode);
	printf("fdpfs_ioring_queue ld->dspec = %u, ld->dtype = %u\n", ld->dspec, ld->dtype);
#endif
	ring->array[tail] = ld->index;
	
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
	
	ret =  io_uring_enter(ld->ring_fd, 1,1, IORING_ENTER_GETEVENTS);
	
	if(ret < 0) {
        perror("io_uring_enter");
        return 1;
    }	

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

#if FDPFS_DEBUG
	printf("msg.ddir = %d\n", msg.ddir);
	printf("msg.size = %zu\n", msg.size); 
	printf("msg.offset = %ld\n", msg.offset);
	printf("msg.slba = %lld\n", msg.slba);

	printf("dev->fd = %d\n", dev->fd);
	printf("dev->nsid = %d\n", dev->nsid);
	printf("ld->ring_fd = %d\n", ld->ring_fd);
	printf("submit_to_sq sqe->opcode = %u\n", IORING_OP_URING_CMD);
	printf("submit_to_sq sqe->cmd_op = %lu\n", NVME_URING_CMD_IO);
#endif
	sqe->user_data = (unsigned long) ld;
	cmd = (struct nvme_uring_cmd *)sqe->cmd;
	ld->nsid = dev->nsid;
	ld->index = index;
	
	/* slba = msg.slba; */
	/* nlb = 1; */	
	
	slba = msg.slba;
	nlb = (msg.size % block_size == 0) ?  msg.size / block_size : msg.size / block_size + 1;
	ld->orig_buffer_size = nlb * block_size; 
	ld->orig_buffer = malloc(ld->orig_buffer_size); 
	
	switch (msg.ddir) {
    	case DDIR_READ:
			ld->ddir = DDIR_READ;
			break;
    	case DDIR_WRITE:
        	ld->ddir = DDIR_WRITE;
			printf("Write msg.buffer = %s\n", msg.buffer);
			ld->orig_buffer = (char*)msg.buffer;
			break;
    	default:
        	return -ENOTSUP;
    }
	
#if FDPFS_DEBUG
	printf("orig_buffer = %s\n", ld->orig_buffer);
	printf("slba = %llu, nlb = %u\n", slba, nlb);
#endif

	return fdpfs_nvme_uring_cmd_prep(cmd, ld, slba, nlb);
}

void *receiver(void *arg) {
	message_t msg;
	struct ioring_data *ld;
    ld = malloc(sizeof(*ld));
	queue_info_t *info = (queue_info_t *)arg;
#if FDPFS_DEBUG
	printf("Initilize Queue id: %d, name: %s \n", info->queue_id, info->name);
#endif
    
	if (!ld){
        perror("malloc");
        return NULL;
    }

    memset(ld, 0, sizeof(*ld));

    if(fdpfs_ioring_queue_init(ld))
		perror("fdpfs_ioring_queue_init_failed\n");	

#if FDPFS_DEBUG
    printf("io_uring_queue_init success\n");
#endif

	while (1) {
		int ret = mq_receive(info->queue_id, (char *) &msg, sizeof(message_t), NULL);
		if (ret == -1) {
			  perror("mq_receive");
			  exit(1);
		}
		submit_to_sq(&dev, ld, msg);
		fdpfs_ioring_queue(ld);
		blocks = read_from_cq(ld);
#if FDPFS_DEBUG
		printf("hey blocks = %s\n", blocks);	
		printf("Queue id: %d, name: %s processing message: %d\n", info->queue_id,info->name, msg.data);
#endif

	}

	num_of_thread++;
	return NULL;
}

static int do_getattr(const char *path, struct stat *statit, struct fuse_file_info* fi) {
	char *pathname;
	pathname=(char *)malloc(strlen(path) + 2);

	strcpy(pathname, path);

	printf("GETATTR %s\n", pathname);

	filetype * file_node = filetype_from_path(pathname);
	if(file_node == NULL)
		return -ENOENT;

	statit->st_uid = file_node -> user_id; 
	statit->st_gid = file_node -> group_id; 
	statit->st_atime = file_node -> a_time; 
	statit->st_mtime = file_node -> m_time; 
	statit->st_ctime = file_node -> c_time;
	statit->st_mode = file_node -> permissions;
	statit->st_nlink = file_node -> num_links + file_node -> num_children;
	statit->st_size = file_node -> size;
	statit->st_blocks = file_node -> blocks;

	return 0;
}

int do_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, 
		struct fuse_file_info *fi, enum fuse_readdir_flags)
{
	printf("READDIR\n");

	filler(buffer, ".", NULL, 0, 0);
	filler(buffer, "..", NULL,0, 0);

	char* pathname = malloc(strlen(path)+2);
	strcpy(pathname, path);

	filetype* dir_node = filetype_from_path(pathname);
	
	printf("pathname = %s\n", pathname);

	if(dir_node == NULL){
		return -ENOENT;
	}
	else{
		dir_node->a_time=time(NULL);
		for(int i = 0; i < dir_node->num_children; i++){
			printf(":%s:\n", dir_node->children[i]->name);
			filler(buffer, dir_node->children[i]->name, NULL, 0, 0);
		}
	}

	return 0;
}

int do_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	printf("READ\n");
	char* pathname = malloc(sizeof(path)+1);
	strcpy(pathname, path);
	filetype* file = filetype_from_path(pathname);
	/* message_t msg; */
	/* int plmt_id = 0; */
	int pos, blk;
	uint32_t n;

	if(file == NULL)
		return -ENOENT;
	
	printf("do_read path = %s, size = %zu, offset=%ld\n", path, size, offset);
	
	for(pos = offset; pos < file->size;){
		// no. of bytes to be written in this block either whole block or few
		n = MIN(block_size - pos % block_size, offset + size - pos);
		
		n = MIN(n, file->size);

		blk = pos/block_size;
		
		printf("blk = %d, pos = %d, n = %d, file->size = %ld\n", blk, pos, n, file->size);
		
		read_block(file, blk, n);
	
		printf("blocks\n");
		
		for(int i=0; i<block_size; i++){
			printf("%c", blocks[i]);
		}

		printf("\n");

		for(int i=0; i<n; i++){
			buf[i] = blocks[i];
		}

		pos += n; // update pos.
		buf += n;
		
		return n;
	}	

	return 0;
}

static int do_mkdir(const char *path, mode_t mode) {
	printf("MKDIR\n");

	int index = find_free_inode();
	
	if(index==-1)
		return -ENOSPC;
	
	filetype* new_folder = malloc(sizeof(filetype));

	char* pathname = malloc(strlen(path)+2);
	strcpy(pathname, path);

	char* rindex = strrchr(pathname, '/');

	strcpy(new_folder -> name, rindex+1);
	strcpy(new_folder -> path, pathname);
	
	*rindex = '\0';

	if(strlen(pathname) == 0)
	strcpy(pathname, "/");

	new_folder->children = NULL;
	new_folder->num_children = 0;
	new_folder->parent = filetype_from_path(pathname);
	new_folder->num_links = 2;
	new_folder->valid = 1;
	strcpy(new_folder->test, "test");

	if(new_folder -> parent == NULL)
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

/* #if FDPFS_DEBUG */
/* 	printf("plmt_id=%d\n", plmt_id); */
/* 	printf("do_write path = %s, buffer = %s, size = %zu, offset=%ld, strlen(buf)=%ld\n", path, buf, size, offset, strlen(buf)); */
/* #endif */

	filetype * file = filetype_from_path(pathname);
	
	if(file == NULL)
		return -ENOENT;
	
	for(pos = offset; pos < offset + size;){
		// no. of bytes to be written in this block either whole block or few
		n = MIN(block_size - pos % block_size, offset + size - pos);

		blk = pos/block_size;

		if(pos + n > file->size)
			file->size = pos + n; 	// update file size accordingly.
		
		printf("blk = %d, pos = %d, n = %d\n", blk, pos, n);
		
		read_block(file, blk, n);
	
		printf("blocks\n");
		for(int i=0; i<block_size; i++){
			printf("%c", blocks[i]);
		}
		printf("\n");

		msg.data = plmt_id; // Set data for the message
		msg.size = n;
		msg.offset = pos;
		msg.ddir = DDIR_WRITE;
		msg.slba = file->datablocks[blk];
		
		printf("buffer\n");
		for(int i=0; i<n; i++){
			printf("blocks --> %c ", blocks[pos+i]);
			blocks[pos + i] = buf[i];
			printf("buf --> %c ", buf[i]);
		}
		printf("\n");

		msg.buffer = blocks; 
		
		int ret = mq_send(queue_infos[plmt_id].queue_id, (const char *) &msg, sizeof(message_t), 0); // Send message
		
		if(ret == -1){
        	perror("mq_send failure at do_write");
			return -EIO;
		}

		pos += n; // update pos.
		buf += n;
		
		printf("file->size = %ld\n", file->size);
	}	

	return size;
}

static void *fdpfs_init(struct fuse_conn_info *conn,
                        struct fuse_config *cfg)
{
	
	(void) conn;
	cfg->kernel_cache = 1;
	cfg->direct_io = 1;

	/* unsigned int nruh = dev.nruh; */
	
	struct nvme_fdp_ruh_status_desc *ruhs = &ruh_status->ruhss[0];
	unsigned int num_of_blocks = le64toh(ruhs->ruamw);
	
	printf("num_of_blocks = %u\n", num_of_blocks);
	initialize_superblock(&spblock, num_of_blocks);
	root = initialize_root_directory(&spblock);
	
	return NULL;
}

int do_create(const char * path, mode_t mode, struct fuse_file_info *fi) {

	printf("CREATEFILE\n");

	int index = find_free_inode();

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

	//new_file -> type = malloc(10);
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

	for(int i = 0; i < 16; i++){
		free_block = find_free_db();
		
		if(free_block == -1)
			return -ENOSPC;

		printf("find free block = %d\n", free_block);
		(new_file->datablocks)[i] = free_block;

	}
	
	new_file->blocks = 0;
	
	return 0;
}

int do_open(const char *path, struct fuse_file_info *fi) {
	char * pathname = malloc(sizeof(path)+1);
	strcpy(pathname, path);
	filetype* file = filetype_from_path(pathname);

	printf("OPEN %s\n", file->name);
	
	return 0;
}


static struct fuse_operations operations = {
    .init = fdpfs_init,
	.getattr	= do_getattr,
    .readdir	= do_readdir,
    .read		= do_read,
    .mkdir		= do_mkdir,
    .write		= do_write,
	.create    	= do_create,
	.open = do_open,
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

void nvme_show_fdp_ruh_status(struct nvme_fdp_ruh_status *status)
{
	uint16_t nruhsd = le16toh(status->nruhsd);	
	
	for (unsigned int i = 0; i < nruhsd; i++) {
        struct nvme_fdp_ruh_status_desc *ruhs = &status->ruhss[i];
        printf("Placement Identifier %"PRIu16"; Reclaim Unit Handle Identifier %"PRIu16"\n",
                le16toh(ruhs->pid), le16toh(ruhs->ruhid));
        printf("  Estimated Active Reclaim Unit Time Remaining (EARUTR): %"PRIu32"\n",
                le32toh(ruhs->earutr));
        printf("  Reclaim Unit Available Media Writes (RUAMW): %"PRIu64"\n",
                le64toh(ruhs->ruamw));
        printf("\n");
    }    
}

static int nvme_passthru_identify(int fd, __u32 nsid, enum nvme_identify_cns cns,
             enum nvme_csi csi, void *data)
{   
    struct nvme_passthru_cmd cmd = {
        .opcode         = nvme_admin_identify,
        .nsid           = nsid,
        .addr           = (__u64)(uintptr_t)data,
        .data_len       = NVME_IDENTIFY_DATA_SIZE,
        .cdw10          = cns,
        .cdw11          = csi << NVME_IDENTIFY_CSI_SHIFT,
        .timeout_ms     = NVME_DEFAULT_IOCTL_TIMEOUT,
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
	/* struct nvme_nvm_id_ns nvm_ns; */
	/* struct ioring_data *ld; */
	/* struct nvme_id_ns ns; */ 
	
	pthread_t threads[NUM_QUEUES];
	
	void *log = NULL;
	int err;
	struct mq_attr attributes;
	attributes.mq_flags = 0; // No specific flags
	attributes.mq_maxmsg = 16; // Max number of messages in queue
	attributes.mq_curmsgs = 0; // Current number of messages (always 0 at creation)
	attributes.mq_msgsize = sizeof(message_t);
	
	struct config {
        __u16   egid;
        __u32   namespace_id;
		char    *output_format;
        bool    human_readable;
        bool    raw_binary;
    };  

    struct config cfg = { 
        .egid       = 0,
        .output_format  = "normal",
        .raw_binary = false,
    }; 
	
	/* Set defaults -- we have to use strdup so that
	   fuse_opt_parse can free the defaults if other
	   values are specified */
	options.filename = strdup("/dev/ng1n1");
	options.contents = strdup("1");
	cfg.egid = (__u16)atoi(options.contents); 

	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
			return 1;

	/* When --help is specified, first print our own file-system
	   specific help text, then signal fuse_main to show
	   additional help (by adding `--help` to the options again)
	   without usage: line (by setting argv[0] to the empty
	   string) */
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
#if FDPFS_DEBUG	
	printf("open fd %d\n", fd);
#endif
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
	err = nvme_get_log_fdp_configurations(fd, cfg.egid, 0,
			            sizeof(hdr), &hdr);
	
 	if(err){
		goto fclose;
	}

	log = malloc(hdr.size);
    
	if (!log) {
        err = -ENOMEM;
        goto fclose;
    }

    err = nvme_get_log_fdp_configurations(fd, cfg.egid, 0,
            hdr.size, log);

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
		printf("error\n");
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
	
	/* nvme_show_fdp_ruh_status(ruh_status); */
	
	num_of_thread = dev.nruh;
	
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
	
	ret = fuse_main(args.argc, args.argv, &operations, NULL);

fclose:
 	// Wait for all consumer threads to finish
#if FDPFS_DEBUG
	printf("fclose\n");
#endif
	for (int i = 0; i < NUM_QUEUES; i++) {
    	if (pthread_join(threads[i], NULL) != 0) {
      		perror("pthread_join");
			exit(1);
    	}
  	} 	
	for (int i = 0; i < NUM_QUEUES; i++) {
    	mq_close(queue_infos[i].queue_id);
    	mq_unlink(queue_infos[i].name); // Remove the queue from the system
  	}	
	
#if FDPFS_DEBUG
	printf("Close file\n");
#endif
	close(fd);
	fuse_opt_free_args(&args);
	return ret;
}
