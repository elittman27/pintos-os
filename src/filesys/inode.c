#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

bool inode_resize(struct inode_disk* id, off_t size);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

struct lock inode_list_lock;

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. 
   Inode lock must be held by current thread already. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  block_sector_t result;
  ASSERT(inode != NULL);
  struct inode_disk* id_disk = calloc(1, sizeof(struct inode_disk));
  // ASSERT(lock_held_by_current_thread(&inode->inode_lock));
  block_read(fs_device, inode->sector, id_disk);

  if (pos < id_disk->length) {
    if (pos < BLOCK_SECTOR_SIZE * 12) { 
      // Direct pointers
      result = id_disk->direct[pos / BLOCK_SECTOR_SIZE];
      free(id_disk);
      return result;
    } else if (pos < (12 + 128) * BLOCK_SECTOR_SIZE) { 
      // Indirect pointer
      block_sector_t direct[128]; // Block of direct pointers
      memset(direct, 0, 512); // Make the buffer certified fresh (I drink 'til I'm drunk (yeah), smoke til I'm high (yeah)…)
      block_read(fs_device, id_disk->indirect, direct);
      
      off_t direct_pos = pos - (12 * BLOCK_SECTOR_SIZE);
      result = direct[direct_pos / BLOCK_SECTOR_SIZE];
      free(id_disk);
      return result;
    } else { 
      // Double indirect pointer
      block_sector_t indirect[128]; // Block of indirect pointers
      block_sector_t direct[128]; // Block of direct pointers
      memset(direct, 0, 512);
      memset(indirect, 0, 512);
      block_read(fs_device, id_disk->dbl_indirect, indirect);
      // Figure out which indirect pointer
      off_t indirect_pos = pos - ((12 + 128) * BLOCK_SECTOR_SIZE);
      int indirect_index = indirect_pos / (128 * BLOCK_SECTOR_SIZE);
      block_read(fs_device, indirect[indirect_index], direct);
      // Figure out which direct pointer within the indirect pointer
      off_t direct_pos = indirect_pos - (indirect_index * 128 * BLOCK_SECTOR_SIZE);
      int direct_index = direct_pos / BLOCK_SECTOR_SIZE;
      result = direct[direct_index];
      free(id_disk);
      return result;
    }
    // return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  } else {
    free(id_disk);
    return -1;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { 
  lock_init(&inode_list_lock);
  list_init(&open_inodes); 
  }

/* Given the index of an indirect pointer, modify the indirect sector,
   such that it contains the correct number of valid direct pointers. */
bool modify_indirect_sector(struct inode_disk* id, block_sector_t* indirect_ptrs, int index, off_t size) {
  block_sector_t* direct_ptrs = calloc(128, sizeof(block_sector_t));
  block_read(fs_device, indirect_ptrs[index], direct_ptrs); // Reads the sector pointed to by indirect ptr in direct_ptrs buffer

  for (int j = 0; j < 128; j++) {
    if (size <= (12 + 128 + index * 128 + j) * BLOCK_SECTOR_SIZE && direct_ptrs[j] != 0) {
      /* Shrink. */
      free_map_release(direct_ptrs[j], 1);
      direct_ptrs[j] = 0;
    } else if (size > (12 + 128 + index * 128 + j) * BLOCK_SECTOR_SIZE && direct_ptrs[j] == 0) {
      /* Grow. */
      if (!free_map_allocate(1, &direct_ptrs[j])) {
        inode_resize(id, id->length);
        free(direct_ptrs);
        return false;
      }
    }
  }
  
  /* Write the updates to the indirect sector back to disk. */
  block_write(fs_device, indirect_ptrs[index], direct_ptrs);
  free(direct_ptrs);
  return true;
}


/* Resizes a inode to the given size. */
bool inode_resize(struct inode_disk* id, off_t size) {
  /* Handle direct pointers. */
  for (int i = 0; i < 12; i++) {
    if (size <= BLOCK_SECTOR_SIZE * i && id->direct[i] != 0) {
      /* Shrink. */
      free_map_release(id->direct[i], 1);
      id->direct[i] = 0;
    } else if (size > BLOCK_SECTOR_SIZE * i && id->direct[i] == 0) {
      /* Grow. */
      if (!free_map_allocate(1, &id->direct[i])) {
        // Rollback if allocation fails 
        inode_resize(id, id->length);
        return false;
      }
    }
  }

  /* Check if indirect pointers are needed. */
  if (id->indirect == 0 && size <= 12 * BLOCK_SECTOR_SIZE) {
    id->length = size;
    return true;
  }

  block_sector_t* buffer = calloc(128, sizeof(block_sector_t));
  if (id->indirect == 0) {
    /* Allocate indirect block. */
    if (!free_map_allocate(1, &id->indirect)) {
      inode_resize(id, id->length);
      free(buffer);
      return false;
    }
  } else {
    /* Read in indirect block. */
    block_read(fs_device, id->indirect, buffer);
  }

  /* Handle indirect pointers. */
  for (int i = 0; i < 128; i++) {
    if (size <= (12 + i) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
      /* Shrink. */
      free_map_release(buffer[i], 1);
      buffer[i] = 0;
    } else if (size > (12 + i) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
      /* Grow. */
      if (!free_map_allocate(1, &buffer[i])) {
        inode_resize(id, id->length);
        free(buffer);
        return false;
      }
    }
  }

  if (size <= 12 * BLOCK_SECTOR_SIZE) {
    /* We shrank the inode such that indirect pointers are not required. */
    free_map_release(id->indirect, 1);
    id->indirect = 0;
  } else {
  /* Write the updates to the indirect block back to disk. */
    block_write(fs_device, id->indirect, buffer);
  }
  free(buffer);

  /* Check if double indirect pointers are needed */
  if (id->dbl_indirect == 0 && size <= 12 * BLOCK_SECTOR_SIZE + BLOCK_SECTOR_SIZE/sizeof(block_sector_t*) * BLOCK_SECTOR_SIZE) {
    id->length = size;
    return true;
  }

  /* Handle double indirect pointers*/
  block_sector_t* indirect_ptrs = calloc(128, sizeof(block_sector_t));
  // Go down first level of indirection
  if (id->dbl_indirect == 0) {
    /* Allocate dbl_indirect block. */
    if (!free_map_allocate(1, &id->dbl_indirect)) {
      inode_resize(id, id->length);
      free(indirect_ptrs);
      return false;
    }
  } else {
    /* Read in first level of dbl_indirect block. */
    block_read(fs_device, id->dbl_indirect, indirect_ptrs); // Buffer now contains array of indirect ptrs
  } 

  // Iterate through each indirect pointer w/in the dbl indirect pointer
  for (int i = 0; i < 128; i++) { 
    // Cases:
    // Partially move within indirect ptr
      // Don't modify the indirect ptr
    // Fully shrink
      // free indirect ptr after modify
    // Fully grow
      // allocate indirect ptr before modify
      // 12 + 128 + 25 <= 12 + 128 (1)*128
    
    if (size <= (12 + 128 + i * 128) * BLOCK_SECTOR_SIZE && indirect_ptrs[i] != 0) {
      // Fully shrink this indirect ptr
      if (!modify_indirect_sector(id, indirect_ptrs, i, size)) {
        free(indirect_ptrs);
        return false;
      }
      free_map_release(indirect_ptrs[i], 1);
      indirect_ptrs[i] = 0;
    } else if (size > (12 + 128 + i * 128) * BLOCK_SECTOR_SIZE && indirect_ptrs[i] == 0) {
      // Fully grow this indirect ptr
      if (!free_map_allocate(1, &indirect_ptrs[i])) {
        inode_resize(id, id->length);
        free(indirect_ptrs);
        return false;
      }
      if (!modify_indirect_sector(id, indirect_ptrs, i, size)) {
        free(indirect_ptrs);
        return false;
      }
      // shrink part 
    } else if (size > (12 + 128 + i * 128) * BLOCK_SECTOR_SIZE 
               && size <= (12 + 128 + (i + 1) * 128) * BLOCK_SECTOR_SIZE 
               && indirect_ptrs[i] != 0) {
      // Partially grow or partially shrink this indirect ptr
      if (!modify_indirect_sector(id, indirect_ptrs, i, size)) {
        free(indirect_ptrs);
        return false;
      }
    }
  }
  
  /* Case if to free the double ind pointer */
  if (size <= (12 + 128) * BLOCK_SECTOR_SIZE) {
    /* We shrank the inode such that this indirect pointer is not required. */
    free_map_release(id->dbl_indirect, 1);
    id->dbl_indirect = 0;
  } else {
  /* Write the updates to the indirect block back to disk. */
    block_write(fs_device, id->dbl_indirect, indirect_ptrs);
  }

  // Closing Statement:
  id->length = size;
  free(indirect_ptrs);
  return true;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    disk_inode->magic = INODE_MAGIC;
    //FIXME ADD SETTING IF ITS A DIRECTORY. 
    success = inode_resize(disk_inode, length);
  
    // Write the disk inode to disk in the sector given to the function
    block_write(fs_device, sector, disk_inode);
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;
  /* Check whether this inode is already open. */
  lock_acquire(&inode_list_lock);
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      lock_release(&inode_list_lock);
      inode_reopen(inode);
      return inode;
    }
  }
  lock_release(&inode_list_lock);

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  lock_init(&(inode->inode_lock));
  lock_acquire(&inode->inode_lock);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_release(&inode->inode_lock);

  // Only cached inodes will have their inode_disk stored in main memory 
  // block_read(fs_device, inode->sector, inode->data); // Their design doc says to take this out
  
  // Only push onto inode list once inode is fully initialized
  lock_acquire(&inode_list_lock);
  list_push_front(&open_inodes, &inode->elem);
  lock_release(&inode_list_lock);

  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL) {
    lock_acquire(&inode->inode_lock);
    inode->open_cnt++;
    lock_release(&inode->inode_lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { 
  block_sector_t temp; 
  lock_acquire(&inode->inode_lock);
  temp = inode->sector;
  lock_release(&inode->inode_lock);
  return temp; 
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;
  
  lock_acquire(&inode->inode_lock);
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    lock_acquire(&inode_list_lock);
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);
    lock_release(&inode_list_lock);

    /* Deallocate blocks if removed. */
    if (inode->removed) { 
      // Read inode disk in from disk and resize to 0
      struct inode_disk* id = calloc(1, sizeof(struct inode_disk));
      block_read(fs_device, inode->sector, id);
      inode_resize(id, 0);
      block_write(fs_device, inode->sector, id);
      // Free the sector
      free_map_release(inode->sector, 1);
      free(id);
      // free_map_release(inode->data->start, bytes_to_sectors(inode->data->length));
    }
    lock_release(&inode->inode_lock);
    free(inode);
    return;
  }
  lock_release(&inode->inode_lock);
  
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  lock_acquire(&inode->inode_lock);
  inode->removed = true;
  lock_release(&inode->inode_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  lock_acquire(&inode->inode_lock);
  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  lock_release(&inode->inode_lock);
  free(bounce);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;
  // TODO potentially get rid of acquired here hacky solution
  int acquired_here = 0;
  if (!lock_held_by_current_thread(&inode->inode_lock)) {
    acquired_here = 1;
    lock_acquire(&inode->inode_lock);
  }
  
  if (inode->deny_write_cnt){
    if (acquired_here) {
      lock_release(&inode->inode_lock);
    }
    return 0;
  } 

  // Check if writing past EOF
  off_t curr_len = inode_length(inode);
  if (curr_len < offset + size) { // Increase inode size
    struct inode_disk* id = calloc(1, sizeof(struct inode_disk));
    block_read(fs_device, inode->sector, id);
    inode_resize(id, offset + size);
    block_write(fs_device, inode->sector, id);
    free(id);
  }
  if (curr_len < offset) { // Fill gap between previous EOF and offset with zeroes
    off_t num_zeroes = offset - curr_len;
    char* zero_buffer = calloc(num_zeroes, sizeof(char));
    inode_write_at(inode, zero_buffer, num_zeroes, curr_len);
    free(zero_buffer);
  }
  
  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      block_write(fs_device, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  if (acquired_here) {
    lock_release(&inode->inode_lock);
  }
  free(bounce);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  lock_acquire(&inode->inode_lock);
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  lock_release(&inode->inode_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  // TODO: figure out why this fixes open-twice test
  lock_acquire(&inode->inode_lock);
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release(&inode->inode_lock);
}

/* Returns the length, in bytes, of INODE's data. 
   Inode lock must be held by current thread already. */
off_t inode_length(const struct inode* inode) {
  off_t temp;
  struct inode_disk* id = calloc(1, sizeof(struct inode_disk));
  // ASSERT(lock_held_by_current_thread(&inode->inode_lock));
  block_read(fs_device, inode->sector, id);
  temp = id->length;
  free(id);
  return temp;
}

// CODE GRAVEYARD💀

/** DEPRECATED**/
/* Given an inode and a byte offset, return the sector pointer contained 
   in the inode to that data. */
/*block_sector_t* offset_to_sector_ptr(struct inode_disk* inode, off_t offset) {
  // TODO: must have the inode lock acquired already.
  block_sector_t buffer[128]; // Holds an indirect block
  memset(buffer, 0, 512);
  //failure case.

  if (offset > 2**23) {
    return NULL;
  } else if (offset < 12 * BLOCK_SECTOR_SIZE) {
    // return direct ptr
    return &inode->direct[offset/BLOCK_SECTOR_SIZE];
  } else if (offset < 12 * BLOCK_SECTOR_SIZE + BLOCK_SECTOR_SIZE/sizeof(block_sector_t*) * BLOCK_SECTOR_SIZE) {
    // return indirect ptr
    block_read(fs_device, inode->indirect, buffer);
    off_t indirect_pos = offset - (12 * BLOCK_SECTOR_SIZE);
    return &buffer[indirect_pos / BLOCK_SECTOR_SIZE];
  } else {
    // dbl indirect
    block_read(fs_device, inode->dbl_indirect, buffer);
    off_t dbl_indirect_pos = offset - (12 * BLOCK_SECTOR_SIZE);
    block_sector_t* indirect_ptr = &buffer[dbl_indirect_pos / (BLOCK_SECTOR_SIZE ** 2)];
    block_read(fs_device, indirect_ptr, buffer);
    // return &buffer[indirect_pos / BLOCK_SECTOR_SIZE];
  }
  
}*/