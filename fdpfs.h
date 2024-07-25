#ifndef FDPFS_H
#define FDPFS_H

struct fdpfs_dev {
	/* Device file path and basename */
	char	*path;
	char	*name;

	/* Flags and features */
	unsigned int flags;
	unsigned long long features;
	unsigned int uid;
	unsigned int gid;
	unsigned int perm;

	/* Device info */
	unsigned int nrg;
	unsigned int nruh;
	unsigned int maxpids;
	unsigned int nnss;
	unsigned int runs;
	unsigned int erutl;
	struct	nvme_fdp_ruh_desc *ruhs;

	/* Device file descriptor */
	int	fd;

	/* Device namespace id */
	int	nsid;
};

/* fdpfs related functions */
void fdpfs_close_dev(struct fdpfs_dev *dev);
int fdpfs_open_dev(struct fdpfs_dev *dev, bool check_overwrite);

#endif /* FDPFS_H */
