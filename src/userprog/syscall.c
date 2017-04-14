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
#include "filesys/file.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

/* Helper functions */
static int get_user (const uint8_t *uaddr); /* function to return a value from user virtual address space */
bool verify_user_ptr(void*vaddr);
void get_args(struct intr_frame *f, int *args, int argc);

/* System call function prototypes */
void system_halt(void);
void system_exit(int status);
pid_t system_exec(const char*cmd_line);
int system_wait(pid_t pid);
bool system_create(const char *file, unsigned initial_size);
bool system_remove(const char *file);
int system_open(const char *file);
int system_filesize(int fd);
int system_read(int fd, void *buffer, unsigned size);
int system_write(int fd, const void *buffer, unsigned size);
void system_seek(int fd, unsigned position);
unsigned system_tell(int fd);
void system_close(int fd);

#define ARG_MAX 3

int syscall_args[ARG_MAX]; // three int array, for max number of arguments in syscall

static struct fd_elem* find_fd(int fd);
static int next_fd(void);

typedef struct fd_elem fd_entry;

struct fd_elem{
   int fd;
   struct file* file;
   struct list_elem elem;
};


struct lock file_lock; // lock for synchronizing access to filesys functions 


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

/* Reads a byte at user virtual address uaddr
   uaddr must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occured
 */
static int get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (result) : "m" (*uaddr));
  return result;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  int callNum; // set up a local variable to hold the call number

  //Verify that the user provided virtual address is valid
  if(verify_user_ptr(f->esp)) {
    // callNum = *((int*)f->esp); // get the call number

    callNum = get_user((uint8_t *)f->esp);

  	// printf ("system call number: %d\n", callNum);
  	//Retrieve and handle the System call NUMBER fromt the User Stack
  	switch(callNum) {
  		case SYS_HALT:
  			system_halt();
        break;
  		case SYS_EXIT:
        get_args(f, syscall_args, 1);
  			system_exit(syscall_args[0]);
  			break;
  		case SYS_EXEC:
        get_args(f, syscall_args, 1);
        f->eax = system_exec((char*)syscall_args[0]);
  			break;
  		case SYS_WAIT:
        get_args(f, syscall_args, 1);
        f->eax = system_wait(*(pid_t*)syscall_args[0]);
  			break;
  		case SYS_CREATE:
        get_args(f, syscall_args, 2);
        f->eax = system_create((char*)syscall_args[0], (unsigned)syscall_args[1]);
  			break;
  		case SYS_REMOVE:
        get_args(f, syscall_args, 1);
        f->eax = system_remove((char*)syscall_args[0]);
  			break;
  		case SYS_OPEN:
        get_args(f, syscall_args, 1);
        f->eax = system_open((char*)syscall_args[0]);//(const char *file);
  			break;
  		case SYS_FILESIZE:
        get_args(f, syscall_args, 1);
        f->eax = system_filesize(syscall_args[0]);
        break;
      case SYS_READ:
        get_args(f, syscall_args, 3);
        f->eax = system_read(syscall_args[0], (void *)syscall_args[1], (unsigned)syscall_args[2]);
  			break;
  		case SYS_WRITE:
        get_args(f, syscall_args, 3);
        f->eax = system_write(syscall_args[0], (void*)syscall_args[1], (unsigned)syscall_args[2]);
  			break;
  		case SYS_SEEK:
        get_args(f, syscall_args, 2);
        system_seek(syscall_args[0], (unsigned)syscall_args[1]);    
  			break;
  		case SYS_TELL:
        get_args(f, syscall_args, 1);
        f->eax = system_tell(syscall_args[0]);
  			break;
  		case SYS_CLOSE:
        get_args(f, syscall_args, 1);
        system_close(syscall_args[0]);
  			break;
		default:
			break;
    }
  }
  thread_exit ();
}


/*************** Start of system call implementations *****************/

void system_halt(void) {
  /* Terminates pintos */
	shutdown_power_off();
}

void system_exit(int status) {
    // printf("Status Number: %d\n", status);
    /* Terminates current user program and returns status to the kernel */
    thread_exit();
}

pid_t system_exec(const char*cmd_line){
  /* runs executable given by cmd_line */
  pid_t id;
  return(id);
}

int system_wait(pid_t pid) {
  printf("sys_wait not implemented");
  return -1;
}

bool system_create(const char *file, unsigned initial_size) {
  
  lock_acquire(&file_lock);
  bool fileCreate = filesys_create (file, (off_t)initial_size);
  lock_release(&file_lock);
  return fileCreate;
}

bool system_remove(const char *file) {
  
  lock_acquire(&file_lock);
  bool fileRemove = filesys_remove(file);
  lock_release(&file_lock);
  return fileRemove;
}

int system_open(const char *file){
  
   lock_acquire(&file_lock);
   struct file *f = filesys_open(file);
   lock_release(&file_lock);
   
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

int system_filesize(int fd) {
  // printf("sys_filesize not implemented");
  struct file* file = find_fd(fd)->file;
  
  lock_acquire(&file_lock);
  int size = (int)file_length (file);
  lock_release(&file_lock);
  return size;
}

int system_read(int fd, void *buffer, unsigned size) {

  // If fd == 0, read from keyboard
  if (fd == STDIN_FILENO) {
    uint8_t *tmp_buffer = (uint8_t *) buffer;
    for(unsigned i = 0; i < size; i++) {
      tmp_buffer[i] = input_getc();
      // (uint8_t *) buffer[i] = input_getc();
    }
    return size;
  }
  
  // Otherwise read from a file
  else {
    struct file* readFile = find_fd(fd)->file;
    
    if (readFile != NULL) {
      lock_acquire(&file_lock);
      int bytesRead = file_read(readFile, buffer, size);
      lock_release(&file_lock);
      return bytesRead;
    }
    else {
      return -1; // file not found
    }
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
      lock_acquire(&file_lock);
      int bytes_written = file_write(find_fd(fd)->file, buffer, size);
      lock_release(&file_lock);
      return bytes_written;
   }
   else {
      // File not found
      return -1;
   }
}

/* Changes where the next byte to be read or written will be in the file */
void system_seek(int fd, unsigned position) {
  
  struct file* file = find_fd(fd)->file;
  
  lock_acquire(&file_lock);
  file_seek (file, (off_t)position);
  lock_release(&file_lock);  
  
}

/* Returns the next position to be read or written from the file */
unsigned system_tell(int fd) {
  
  struct file* file = find_fd(fd)->file;
  
  lock_acquire(&file_lock);
  unsigned position = (unsigned)file_tell (file);
  lock_release(&file_lock);
  
  return position;
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


/************** End of  implementations ********************/


/* Start Helper Functions */
bool verify_user_ptr(void *vaddr) {
	bool isValid = 1;
	if(is_user_vaddr(vaddr) && (vaddr < ((void*)LOWEST_USER_VADDR))){
		isValid = 0;	
	}

	return (isValid);
}



/* Retrieve arguments from stack */
void get_args(struct intr_frame *f, int *args, int argc) {

  int *argptr; // pointer to argument

  for (int i = 0; i < argc; i++) {
    argptr = (int*)f->esp + (4 * i);
    if(verify_user_ptr((void *)argptr)) {
      args[i] = *argptr; // put the contents of argument pointer into array or args
    }
    else {
      // system_exit();
    }
  }
}
