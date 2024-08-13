enum {
	FDPFS_IO_URING = 0,
	FDPFS_FUSE,
	FDPFS_DEVICE,
	FDPFS_DEBUG_MAX,
};

struct debug_level {
	const char *name;
	const char *help;
	unsigned long shift;
	unsigned int jobno;
};

extern const struct debug_level debug_levels[];

extern unsigned long fio_debug;

extern FILE *f_out;

void __dprint(int type, const char *str, ...) __attribute__((format (printf, 2, 3)));

#define dprint(type, str, args...)	\
do{                        \
	if (((1 << type) & fio_debug) == 0)	\
		break;	\
	__dprint((type), (str), ##args);	\
} while (0)    
