#include "io_uring.h"

int fdpfs_ioring_queue_init(struct ioring_data* ld){
	struct io_uring_params p;
	int ret;
	int depth = 1;

	memset(&p, 0, sizeof(p));

	p.flags |= IORING_SETUP_SQE128;
	p.flags |= IORING_SETUP_CQE32;

	/*
	 * Clamp CQ ring size at our SQ ring size, 
	 * we don't need more entries than that.
	*/
	p.flags |= IORING_SETUP_CQSIZE;
	p.cq_entries = depth;

	/*
	 * Setup COOP_TASKRUN as we don't need to get IPI interrupted for
	 * completing IO operations.
	*/
	p.flags |= IORING_SETUP_COOP_TASKRUN;
	
	/*
	 * io_uring is always a single issuer, and we can defer task_work
	 * runs until we reap events.
	*/
	p.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
    
	ret = syscall(__NR_io_uring_setup, depth, &p);
    
	if(ret < 0) {
		perror("io_uring_setup failed");
		return ret;	
	}
	
	ld->ring_fd = ret;	
#if FDPFS_DUBUG 
	printf("fdpfs_ioring_queue_init ld->ring_fd = %d\n", ld->ring_fd);
#endif
	fdpfs_ioring_probe(ld->ring_fd);
	
	return fdpfs_ioring_mmap(ld, &p);
}

void fdpfs_ioring_probe(int ring_fd){
	struct io_uring_probe *p;
	int ret;

	p = calloc(1, sizeof(*p) + 256 * sizeof(struct io_uring_probe_op));
	
	if (!p)
		return;
    
	ret = syscall(__NR_io_uring_register, ring_fd,
            IORING_REGISTER_PROBE, p, 256);
    
	if (ret < 0){
		perror("io_uring_probe failed");
		goto out;
	}
out:
	free(p);
}

int fdpfs_ioring_mmap(struct ioring_data *ld, struct io_uring_params *p)
{   
	struct io_sq_ring *sring = &ld->sq_ring;
	struct io_cq_ring *cring = &ld->cq_ring;
	void *sq_ptr, *cq_ptr;

	int sring_sz = p->sq_off.array + p->sq_entries * sizeof(__u32);
	int cring_sz = p->cq_off.cqes + p->cq_entries * sizeof(struct io_uring_cqe);

	/*
	 * Map in the submission and completion queue ring buffers.
	 * Older kernels only map in the submission queue, though.
	*/

	sq_ptr = mmap(0, sring_sz, PROT_READ | PROT_WRITE, 
			MAP_SHARED | MAP_POPULATE, 
			ld->ring_fd, IORING_OFF_SQ_RING);
	
	if (sq_ptr == MAP_FAILED) {
		perror("mmap failed");
		return 1;
	}	

	/*
	 * Save useful fields in a global app_io_sq_ring struct for later 
	 * easy reference 
	*/
    sring->head = sq_ptr + p->sq_off.head;
    sring->tail = sq_ptr + p->sq_off.tail;
    sring->ring_mask = sq_ptr + p->sq_off.ring_mask;
    sring->ring_entries = sq_ptr + p->sq_off.ring_entries;
    sring->flags = sq_ptr + p->sq_off.flags;
    sring->array = sq_ptr + p->sq_off.array;
	
	/* Map in the submission queue entries array */
    ld->sqes = mmap(0, p->sq_entries * sizeof(struct io_uring_sqe),
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
            ld->ring_fd, IORING_OFF_SQES);
    
	if (ld->sqes == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
	
	cq_ptr = mmap(0, cring_sz, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, ld->ring_fd, IORING_OFF_CQ_RING);

	/*
	 * Save useful fields in a global app_io_cq_ring struct for later
	 * easy reference 
	*/
	cring->head = cq_ptr + p->cq_off.head;
	cring->tail = cq_ptr + p->cq_off.tail;
	cring->ring_mask = cq_ptr + p->cq_off.ring_mask;
	cring->ring_entries = cq_ptr + p->cq_off.ring_entries;
	cring->cqes = cq_ptr + p->cq_off.cqes;

	return 0;
}


int io_uring_enter(int ring_fd, unsigned int to_submit,
                          unsigned int min_complete, unsigned int flags)
{
	return (int)syscall(__NR_io_uring_enter, ring_fd, to_submit, 
			min_complete, flags, NULL, 0);
}
