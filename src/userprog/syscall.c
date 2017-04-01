#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "lib/user/syscall.h"

static void syscall_handler (struct intr_frame *);
bool verify_user_ptr(void*vaddr);
void system_halt(void);
void system_exit(int status);
int system_open(const char *file);
void system_close(int fd);
int system_write(int fd, const void *buffer, unsigned size);
pid_t system_exec(const char*cmd_line);

void
syscall_init (void) 
{
	/*Need to Implement Syncronization*/
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  //Verify that the user provided virtual address is valid
  if(verify_user_ptr(f->esp)) {

  }
  thread_exit ();
}

void system_halt(void) {
	shutdown_power_off();
}

void system_exit(int status) {
        thread_exit();
}

int system_open(const char *file){
   struct file *f = filesys_open(file);
   if (f == NULL){
      return -1;
   }

   // Create new file descriptor
   struct fd_elem *fde = malloc(sizeof(struct fd_elem));
   if (fde == NULL){
      return -1;
   }

   // Increment file descriptor
   fde->fd = thread_current()->fd_count;
   // Adjust thread fd counter
   thread_current()->fd_count += 1;
   // Save file with fd struct
   fde->file = f;
   // Add to threads open file list
   list_push_back(&thread_current()->fd_list, &fde->elem);

   // Return file descriptor
   return fde->fd;

}

void system_close(int fd){
   if (find_fd(fd) != NULL){
      struct fd_elem *fde = find_fd(fd);
      // Close file
      file_close(fde->file);
      // Remove from open file list
      list_remove(&fde->elem);
      // Free memory
      free(fde);
   }
}

int system_write(int fd, const void *buffer, unsigned size){
   // Write to console
   if (fd == STDOUT_FILENO){
      if (size <= 300){
         putbuf((char *)buffer, (size_t) size);
      }
      else {
         unsigned t_size = size;
         while (t_size > 300){
            putbuf((char *)buffer, (size_t) t_size);
            t_size -= 300;
         }
         putbuf((char *)buffer, (size_t) t_size);
      }
      return (int)size;
   }
   // Write to file
   if (find_fd(fd) != NULL){
      int bytes_written = write_file(find_fd(fd)->file, buffer, size);
      return bytes_written;
   }
   else {
      // File not found
      return -1;
   }
}

pid_t system_exec(const char*cmd_line){
	pid_t id;
	return(id);
}

bool verify_user_ptr(void *vaddr) {
	bool isValid = 1;
	if(is_user_vaddr(vaddr) || (vaddr < ((void*)LOWEST_USER_VADDR))){
		isValid = 0;	
	}

	return (isValid);
}


