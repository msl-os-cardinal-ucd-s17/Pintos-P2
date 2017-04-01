#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/*Defines the lowest possible virtual address a user program can occupy without encroaching 
on code segment of address space
Note: cast the virtual address as a void* pointer, which we can perform (in)equality and equality operations
to compare validty*/
#define LOWEST_USER_VADDR 0x08048000

void syscall_init (void);

#endif /* userprog/syscall.h */
