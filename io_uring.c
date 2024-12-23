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
	void *ptr;

	ld->mmap[0].len = p->sq_off.array + p->sq_entries * sizeof(__u32);
	ptr = mmap(0, ld->mmap[0].len, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_POPULATE, ld->ring_fd,
		IORING_OFF_SQ_RING);
	ld->mmap[0].ptr = ptr;
	sring->head = ptr + p->sq_off.head;
	sring->tail = ptr + p->sq_off.tail;
	sring->ring_mask = ptr + p->sq_off.ring_mask;
	sring->ring_entries = ptr + p->sq_off.ring_entries;
	sring->flags = ptr + p->sq_off.flags;
	sring->array = ptr + p->sq_off.array;
	ld->sq_ring_mask = *sring->ring_mask;

	if (p->flags & IORING_SETUP_SQE128)
		ld->mmap[1].len = 2 * p->sq_entries * sizeof(struct io_uring_sqe);
	else
		ld->mmap[1].len = p->sq_entries * sizeof(struct io_uring_sqe);
	
	ld->sqes = mmap(0, ld->mmap[1].len, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, ld->ring_fd,
			IORING_OFF_SQES);
	ld->mmap[1].ptr = ld->sqes;

	if (p->flags & IORING_SETUP_CQE32) {
		ld->mmap[2].len = p->cq_off.cqes +
				2 * p->cq_entries * sizeof(struct io_uring_cqe);
	} else {
		ld->mmap[2].len = p->cq_off.cqes +
				p->cq_entries * sizeof(struct io_uring_cqe);
	}
	ptr = mmap(0, ld->mmap[2].len, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_POPULATE, ld->ring_fd,
		IORING_OFF_CQ_RING);
	ld->mmap[2].ptr = ptr;
	cring->head = ptr + p->cq_off.head;
	cring->tail = ptr + p->cq_off.tail;
	cring->ring_mask = ptr + p->cq_off.ring_mask;
	cring->ring_entries = ptr + p->cq_off.ring_entries;
	cring->cqes = ptr + p->cq_off.cqes;
	ld->cq_ring_mask = *cring->ring_mask;
	return 0;
}


int io_uring_enter(int ring_fd, unsigned int to_submit,
                          unsigned int min_complete, unsigned int flags)
{
	return (int)syscall(__NR_io_uring_enter, ring_fd, to_submit, 
			min_complete, flags, NULL, 0);
}
