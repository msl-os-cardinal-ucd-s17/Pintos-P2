#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "lib/user/syscall.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"

#define arg0    ((f->esp)-4)
#define arg1	((f->esp)-8)
#define arg2	((f->esp)-12)
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
static void syscall_handler (struct intr_frame *);
bool verify_user_ptr(void*vaddr);
void system_halt(void);
void system_exit(int status);
int system_open(const char *file);
void system_close(int fd);
int system_write(int fd, const void *buffer, unsigned size);
pid_t system_exec(const char*cmd_line);
int system_open(const char *file);
void system_close(int fd);
int system_write(int fd, const void *buffer, unsigned size);
pid_t system_exec(const char*cmd_line);

static struct fd_elem* find_fd(int fd);
static int next_fd(void);

typedef struct fd_elem fd_entry;

struct fd_elem{
   int fd;
   struct file* file;
   struct list_elem elem;
};


// Check current thread's list of open files for fd
static struct fd_elem* find_fd(int fd){
   struct list_elem *e;
   struct fd_elem *fde = NULL;
   struct list *fd_elems = &thread_current()->fd_list;

   for (e = list_begin(fd_elems); e != list_end(fd_elems); e = list_next(e)){
      struct fd_elem *t = list_entry (e, struct fd_elem, elem);
      if (t->fd == fd){
         fde = t;
         break;
      }
   }

   return fde;
}

static int next_fd(void){
   return thread_current()->fd_count++;
}


static struct fd_elem* find_fd(int fd);
static int next_fd(void);

typedef struct fd_elem fd_entry;

struct fd_elem{
   int fd;
   struct file* file;
   struct list_elem elem;
};


// Check current thread's list of open files for fd
static struct fd_elem* find_fd(int fd){
   struct list_elem *e;
   struct fd_elem *fde = NULL;
   struct list *fd_elems = &thread_current()->fd_list;

   for (e = list_begin(fd_elems); e != list_end(fd_elems); e = list_next(e)){
      struct fd_elem *t = list_entry (e, struct fd_elem, elem);
      if (t->fd == fd){
         fde = t;
         break;
      }
   }

   return fde;
}

static int next_fd(void){
   return thread_current()->fd_count++;
}



void
syscall_init (void) 
{
	/*Need to Implement Syncronization*/
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int call_status = -1;

  //Verify that the user provided virtual address is valid
  if(verify_user_ptr(f->esp)) {
  	  printf ("system call number: %d\n", *((int*) f->esp));

  	//Retrieve and handle the System call NUMBER fromt the User Stack
  	switch(*((int*) f->esp)) {
  		case SYS_HALT:
  			system_halt();
  			break;
  		case SYS_EXIT:
			if (verify_user_ptr(f->esp + 4)){
				system_exit(*((int *)f->esp + 4));
				call_status = 0;	
			}
			break;
  		case SYS_EXEC:
  			break;
  		case SYS_WAIT:
  			break;
  		case SYS_CREATE:
  			break;
  		case SYS_REMOVE:
  			break;
  		case SYS_OPEN:
			if (verify_user_ptr(f->esp + 4)){
                                system_open(*((int *)f->esp + 4));
                                call_status = 0;
                        }
  			break;
  		case SYS_FILESIZE:
  			break;
  		case SYS_READ:
  			break;
  		case SYS_WRITE:
			if (verify_user_ptr(f->esp + 4)){
				if (verify_user_ptr(f->esp + 8)){
					if (verify_user_ptr(f->esp + 12)){
						call_status = system_write(*((int *)f->esp + 4), *((int *)f->esp + 8), *((int *)f->esp + 12));
					}
				}
                        }
  			break;
  		case SYS_SEEK:
  			break;
  		case SYS_TELL:
  			break;
  		case SYS_CLOSE:
  			break;
		default:
			break;
  	}
  }
  
  if (call_status == -1){
  	thread_exit ();
  }
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
   struct fd_elem *fde = malloc (sizeof(struct fd_elem));
   if (fde == NULL){
      return -1;
   }

   // Increment file descriptor
   fde->fd = next_fd(); 
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
      int bytes_written = file_write(find_fd(fd)->file, buffer, size);
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
	if(is_user_vaddr(vaddr) && (vaddr < ((void*)LOWEST_USER_VADDR))){
		isValid = 0;	
	}

	return (isValid);
}

