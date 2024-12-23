#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* If your compilation fails because the header file below is missing,
 *  * your kernel is probably too old to support io_uring.
 *   * */
#include <linux/io_uring.h>

#define FDP_DIR_DTYPE 2

#define NVME_IDENTIFY_CSI_SHIFT 24

enum fdpfs_ddir {
	DDIR_READ = 0,
	DDIR_WRITE = 1,
	DDIR_TRIM = 2,
	DDIR_SYNC = 3,
	DDIR_DATASYNC,
	DDIR_SYNC_FILE_RANGE,
	DDIR_WAIT,
	DDIR_LAST,
	DDIR_INVAL = -1,
	DDIR_TIMEOUT = -2,

	DDIR_RWDIR_CNT = 3,
	DDIR_RWDIR_SYNC_CNT = 4,
};  

struct io_sq_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	unsigned *flags;
	unsigned *array;
};

struct io_cq_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	struct io_uring_cqe *cqes;
};

struct ioring_mmap{
	void *ptr;
	size_t len;
};

struct ioring_data {
	int ring_fd;

	/* struct io_u **io_u_index; */
	/* char *md_buf; */

	/* int *fds; */

	struct io_sq_ring sq_ring;
	struct io_uring_sqe *sqes;
	/* struct iovec *iovecs; */
	unsigned sq_ring_mask;

	struct io_cq_ring cq_ring;
	enum fdpfs_ddir ddir;

	uint32_t dtype;
	uint32_t dspec;

	/* Device namespace id */
	int nsid;

	unsigned index;


	char *orig_buffer;
	size_t orig_buffer_size;

	unsigned cq_ring_mask;

	/* int queued; */
	/* int cq_ring_off; */
	/* unsigned iodepth; */
	/* int prepped; */

	struct ioring_mmap mmap[3];

	/* struct cmdprio cmdprio; */

	/* struct nvme_dsm_range *dsm; */
};

void fdpfs_ioring_probe(int ring_fd);
int fdpfs_ioring_mmap(struct ioring_data* ld, struct io_uring_params *p);
int fdpfs_ioring_queue_init(struct ioring_data* ld);
int io_uring_enter(int ring_fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags);
