LINUX_SOURCE = ../linux-6.7.9
LIBFUSE = ../fuse-3.16.2
LIBNVME = ../libnvme-1.8

LDLIBS = -lnvme -lblkid

MKFS = mkfs.fdpfs

CFILES := mkfs.c io_uring.c super.c

all: $(CFILES)
	rm -f $(MKFS)
	$(CC) -D_GNU_SOURCE -std=gnu99 -Wall -o $(MKFS) $(CFILES) $(LDLIBS) -pthread `pkg-config fuse3 --cflags --libs`

debug: $(CFILES)
	rm -f $(MKFS)
	$(CC) -D_GNU_SOURCE -D FDPFS_DEBUG -std=gnu99 -Wall -o $(MKFS) $(CFILES) $(LDLIBS) -pthread `pkg-config fuse3 --cflags --libs`

ctags:
	rm -f tags
	ctags -R * -L $(LINUX_SOURCE)/include/* $(LIBFUSE)/include/* $(LIBNVME)/src/*

clean:
	rm -f $(MKFS)

.PHONY: all clean
