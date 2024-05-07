#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/process.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

/* Directory Related Functions */
/* Given a path to a file, return the file's parent directory as an open inode
  and set result_filename (a pointer to a string that has been allocated)
  to its relative name */
struct inode* get_relative_dir_inode(const char* path, char** result_filename){
  if (strlen(path) == 0) {
    return NULL;
  }
  struct thread* t = thread_current();
  char next_file_part[NAME_MAX + 1];
  char curr_file_part[NAME_MAX + 1]; // = root_dir_name; // deal with '/' case
  // Set initial curr_inode
  struct inode* curr_inode;
  if (path[0] == '/') { // Full path was passed in
    curr_inode = inode_open(ROOT_DIR_SECTOR);
    // Path is "/"
    if (strlen(path) == 1) {
      strlcpy(*result_filename, ".", 2);
      return curr_inode;
    }
  } else {
    curr_inode = inode_reopen(t->pcb->cwd_inode);
  }

  // Set vars before loop

  struct inode* next_inode = calloc(1, sizeof(struct inode));

  // Confirm that entire path except for last item is a valid directory
  while (get_next_part(next_file_part, &path)) {
    strlcpy(curr_file_part, next_file_part, NAME_MAX + 1);
    // Check if valid inode
    if(curr_inode->removed){
      inode_close(curr_inode);
      free(next_inode); // WE KNOW UV THE THROAT GOAT
      return NULL;
    }

    // Check if path exists a/b/c where c doesnt exist this is for mkdir
    struct dir* curr_dir = dir_open(curr_inode);
    if (!dir_lookup(curr_dir, next_file_part, &next_inode)) { // Sets next inode
      if (!get_next_part(next_file_part, &path)) { // Path doesn't exist but you're on the last part
        break;
      }
      // bad path: i.e. a/x/c where x does not exist
      inode_close(curr_inode);
      free(next_inode);
      return NULL;
    }

    // Read in the inode disk from entry (an inode)
    struct inode_disk* id_disk = calloc(1, sizeof(struct inode_disk));
    block_read(fs_device, next_inode->sector, id_disk);

    // Check if its a directory.
    if (!id_disk->is_dir) {
      if (!get_next_part(next_file_part, &path)) {
        break;
      }
      // malformed path: i.e. a/b.txt/c
      inode_close(curr_inode);
      inode_close(next_inode);
      return NULL;
    } else {
      // Is a directory but check if on the last part i.e. /a/b
      if(strlen(path) == 0){
        break;
      }
    }

    // inode_close(curr_inode);
    curr_inode = next_inode;
    dir_close(curr_dir);
  }

  strlcpy(*result_filename, curr_file_part, strlen(curr_file_part)+1);
  return curr_inode;
};


/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
  struct thread* curr = thread_current();
  curr->pcb->cwd_inode = inode_open(ROOT_DIR_SECTOR);


  // Set up Root Directory Properly:
  struct dir* root_dir = dir_open_root();
  char temp_name[15];
  dir_add(root_dir, ".", ROOT_DIR_SECTOR); // Add .
  dir_add(root_dir, "..", ROOT_DIR_SECTOR); // Add ..
  //TODO FIXME but it might work with the two lines above
  // //Add ..
  // if (!dir_add(root_dir, "..", ROOT_DIR_SECTOR)) {
  //   PANIC("Failed to add '..' to the root directory.");
  // }

  // // Add .
  // if (!dir_add(root_dir, ".", ROOT_DIR_SECTOR)) {
  //   PANIC("Failed to add '.' to the root directory.");
  // }


  struct inode_disk* id_disk = calloc(1, sizeof(struct inode_disk));
  block_read(fs_device, ROOT_DIR_SECTOR, id_disk);
  id_disk->is_dir = true;
  block_write(fs_device, ROOT_DIR_SECTOR, id_disk);

  free(id_disk);

  dir_close(root_dir);
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { free_map_close(); }

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  block_sector_t inode_sector = 0;
  char* relative_name = (char*) malloc(sizeof(char) * (NAME_MAX + 1));
  struct inode* dir_inode = get_relative_dir_inode(name, &relative_name);
  struct dir* dir = dir_open(dir_inode);

  struct inode* temp;
  if (dir_inode == NULL) {
    free(relative_name);
    return false;
  }
  // Case where relative name already exists in the directory
  if (dir_lookup(dir, relative_name, &temp)) {
    free(relative_name);
    dir_close(dir);
    return false;
  }

  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size) && dir_add(dir, relative_name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);
  free(relative_name);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  //review TODO
  char* relative_name = (char*) malloc(sizeof(char) * (NAME_MAX + 1));
  struct inode* dir_inode = get_relative_dir_inode(name, &relative_name);
  struct dir* dir = dir_open(dir_inode);
  // struct dir* dir = dir_open_root();
  struct inode* inode = NULL;
  if (dir != NULL) {
    dir_lookup(dir, relative_name, &inode);
  }
  dir_close(dir);
  free(relative_name);
  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  // Trying to remove root
  if (!strcmp(name, "/")) {
    return false;
  }
  char* relative_name = (char*) malloc(sizeof(char) * (NAME_MAX + 1));
  struct inode* dir_inode = get_relative_dir_inode(name, &relative_name);
  struct dir* dir = dir_open(dir_inode);

  // Check if trying to remove a directory
  struct inode_disk* id_disk = calloc(1, sizeof(struct inode_disk));
  block_read(fs_device, dir_inode->sector, id_disk);
  bool success;
  if (id_disk->is_dir) { // Trying to remove a directory
    // Go into that directory and then read it
    struct inode* dest_inode = calloc(1, sizeof(struct inode));
    dir_lookup(dir, relative_name, &dest_inode); // Set the dest_inode
    struct dir* dest_dir = dir_open(dest_inode);
    char* curr_name = (char*) malloc(sizeof(char) * (NAME_MAX + 1));
    // Check only . and .. in directory and if true then remove directory.
    while (dir_readdir(dest_dir, curr_name)) {
      int is_not_dot = strcmp(curr_name, ".");
      int is_not_dot_dot = strcmp(curr_name, "..");
      if (is_not_dot && is_not_dot_dot) {
        dir_close(dir);
        dir_close(dest_dir);
        free(relative_name);
        free(curr_name);
        return false;
        } // TODO deal with case where directory has files marked as removed and should still delete it
    }
    dir_close(dest_dir);
    free(curr_name);
  }

  success = dir != NULL && dir_remove(dir, relative_name);
  dir_close(dir);
  free(relative_name);
  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

int mkdir(const char* path) {
  // Get the relative directory first
  char* relative_name = (char*) malloc(sizeof(char) * (NAME_MAX + 1));
  struct inode* parent_inode = get_relative_dir_inode(path, &relative_name);
  struct dir* parent_dir = dir_open(parent_inode);
  struct inode* temp;
  if (parent_inode == NULL) {
    free(relative_name);
    return false;
  }
  // Case where relative name already exists in parent inode
  if (dir_lookup(parent_dir, relative_name, &temp)) {
    free(relative_name);
    dir_close(parent_dir);
    return false;
  }

  // Build the new directory we are adding
  struct dir* new_dir = calloc(1, sizeof(struct dir));
  new_dir->pos = 0;

  block_sector_t new_sector;
  if (!free_map_allocate(1, &new_sector)) {
    free(new_dir);
    dir_close(parent_dir);
    return false;
  }
  if (!dir_create(new_sector, 0)) {
    free(new_dir);
    dir_close(parent_dir);
    return false;
  }

  struct inode_disk* id_disk = calloc(1, sizeof(struct inode_disk));
  block_read(fs_device, new_sector, id_disk);
  id_disk->is_dir = true;
  block_write(fs_device, new_sector, id_disk);
  free(id_disk);
  new_dir->inode = inode_open(new_sector);

  // Add ..
  if (!dir_add(new_dir, "..", parent_inode->sector)) {
    free(relative_name);
    free(new_dir);
    dir_close(parent_dir);
    return false;
  }

  // Add .
  if (!dir_add(new_dir, ".", new_dir->inode->sector)) {
    free(relative_name);
    free(new_dir);
    dir_close(parent_dir);
    return false;
  }

  // Add new directory to its parent directory
  // parent_dir = dir_open(parent_inode);
  dir_add(parent_dir, relative_name, new_sector);
  free(relative_name);
  free(new_dir);
  dir_close(parent_dir);
  return true;
}

int chdir(const char* path) {
  char* relative_name = (char*) malloc(sizeof(char) * (NAME_MAX + 1));
  struct inode* parent_inode = get_relative_dir_inode(path, &relative_name);
  struct dir* parent_dir = dir_open(parent_inode);

  struct inode* dest_inode = calloc(1, sizeof(struct inode));
  if (parent_dir == NULL || !dir_lookup(parent_dir, relative_name, &dest_inode)) {
    // Error last level of directory structure doesn't exist
    free(relative_name);
    dir_close(parent_dir);
    inode_close(dest_inode);
    return false;
  }

  // Check that the dest_inode is a directory and not a file
  struct inode_disk* id_disk = calloc(1, sizeof(struct inode_disk));
  block_read(fs_device, dest_inode->sector, id_disk);
  if(!id_disk->is_dir){
    free(relative_name);
    dir_close(parent_dir);
    inode_close(dest_inode);
    free(id_disk);
    return false;
  }
  free(id_disk);

  //set process cwd_inode to be dest_inode
  thread_current()->pcb->cwd_inode = dest_inode;
  return true;
}
