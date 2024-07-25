#include "super.h"

void initialize_superblock(superblock* spblock, unsigned int num_of_blocks){
	spblock->data_bitmap = malloc(num_of_blocks*sizeof(char));
	memset(spblock->data_bitmap, '0', num_of_blocks*sizeof(char));
	memset(spblock->inode_bitmap, '0', 100*sizeof(char));
}

filetype* initialize_root_directory(superblock* spblock) {
	filetype * root;
	spblock->inode_bitmap[1] = '1'; //marking it with 0
	root = (filetype *)malloc(sizeof(filetype));

	strcpy(root->path, "/");
	strcpy(root->name, "/");

	root->children = NULL;
	root->num_children = 0;
	root->parent = NULL;
	root->num_links = 2;
	root->valid = 1;
	
	strcpy(root->test, "test");
	strcpy(root->type, "directory");

	root->c_time = time(NULL);
	root->a_time = time(NULL);
	root->m_time = time(NULL);
	root->b_time = time(NULL);

	root->permissions = S_IFDIR | 0777;

	root->size = 0;
	root->group_id = getgid();
	root->user_id = getuid();

	root->number = 2;
	root->blocks = 0;

	return root;
}
