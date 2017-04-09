#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/fixed-point.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

#include "devices/timer.h"

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

#define DONATION_DEPTH_LIMIT 8

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

// ****************************************************************
// List of sleeping threads. Sorting into ascending wake up time.
// The first element in the list will be the next thread to wake up.
static struct list sleep_list;

// ****************************************************************
//List of threads based on ascending priority. The first element in the list
//is the element with the highest priority.
/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

/* System load average */
struct fixed_point load_average;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

struct thread *get_thread(tid_t tid); /* Get thread by tid from all_list */
struct thread *get_child(tid_t tid); /* Get thread by tid from thread's child_list */
void init_synchronization(struct thread *t); /* Initialize synchronization variables */

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);

  list_init (&ready_list);
  list_init (&all_list);
  list_init (&sleep_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();

  init_synchronization(initial_thread);
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Set initial load average to 0 */
  load_average.value = 0;

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
	
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Initialize synchronization variables */
  init_synchronization(t);

  old_level = intr_disable();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level(old_level);

  /* Add to run queue. */
  thread_unblock (t);
	
  //Verify that the current thread is highest priority
  old_level = intr_disable();
  verify_current_thread_highest();
  intr_set_level(old_level);

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  add_thread_ready_priority_list(t);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) {
    add_thread_ready_priority_list(cur);
  }
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  enum intr_level old_level = intr_disable ();
  /* Ignore if mlfqs option is set */
  if (!thread_mlfqs)
  {
    struct thread *cur_t = thread_current();
    int previous_priority = cur_t->effective_priority;
    cur_t->priority = new_priority;
    
    // Updates effective_priority in consideration of the threads blocked on its lock.
    thread_priority_synchronize();
    
    if (previous_priority < cur_t->effective_priority)
    {
      // If the current thread's priority was upgraded, 
      //  priority inversion could happen on any threads blocked by a lock held by the current_thread.
      //  Thus, propagate the priority down the blocked threads (inc. threads blocked by lock chaining).
      thread_donate_priority();
    }
    else
    {
      // Else, if the current thread's priority was potentially downgraded, 
      //   yield to ensure the highest priority thread is executing.
       verify_current_thread_highest();
    }
  }
  intr_set_level (old_level);
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->effective_priority;
}

/* Propagate down the threads who are blocked on a chain of locks. */
void
thread_donate_priority (void)
{
  ASSERT (!thread_mlfqs);
  int depth = 0;
  struct thread *cur_thread = thread_current();
  struct lock *cur_lock = cur_thread->blocking_lock;
  while (cur_lock != NULL && depth < DONATION_DEPTH_LIMIT && cur_lock->holder != NULL && (cur_lock->holder)->effective_priority < cur_thread->effective_priority)
  {
    ++depth;
    (cur_lock->holder)->effective_priority = cur_thread->effective_priority;
    cur_thread = cur_lock->holder;
    cur_lock = cur_thread->blocking_lock;
  }
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int new_nice) 
{
  ASSERT(thread_mlfqs);

  /* Disable interrupts */
  enum intr_level old_level = intr_disable ();

  /* Set nice */
  thread_current ()->nice = new_nice;
  
  /* Recalculate thread's priority */
  m_priority (thread_current ()); 
  
  verify_current_thread_highest();

  /* Restore interrupt level */
  intr_set_level (old_level);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  ASSERT(thread_mlfqs);
  enum intr_level old_level = intr_disable ();
  int return_nice = thread_current ()->nice;
  intr_set_level (old_level);
  return return_nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  ASSERT(thread_mlfqs);
  return fixed_to_int_roundInt(fixed_mult_int(load_average,100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  ASSERT(thread_mlfqs);
  enum intr_level old_level = intr_disable ();
  int recent_cpu_times_hundred = thread_current()->recent_cpu * 100;
  intr_set_level (old_level);
  return recent_cpu_times_hundred;
}

/* Calculates thread priority when mlfqs option is set. */
void
m_priority(struct thread *t)
{
  ASSERT(thread_mlfqs);

  if (t != idle_thread)
  {
    /* Priority = PRI_MAX - (recent_cpu/4) - (nice*2) */
    struct fixed_point term1 = int_to_fixed(PRI_MAX);
    int term2 = t->recent_cpu / 4;
    int term3 = (t->nice * 2);
    term1 = fixed_minus_int(term1, term2);
    term1 = fixed_minus_int(term1, term3);

    /* Update thread's priority with result */  
    t->effective_priority = fixed_to_int_round0(term1);

    /* Bounds check */
    if (t->effective_priority < PRI_MIN)
    {
      t->effective_priority = PRI_MIN;
    }
    if (t->effective_priority > PRI_MAX)
    {
      t->effective_priority = PRI_MAX;
    }
  }
}

/* Recalculates mlfqs recent_cpu and priority for all threads (running, blocked, idle). */
void 
recalc_mlfqs (void)
{
  ASSERT(thread_mlfqs);

  struct list_elem *l;
  for (l = list_begin(&all_list); l != list_end(&all_list); l = list_next(l))
  {
    struct thread *t = list_entry(l, struct thread, allelem);
    calc_recent_cpu(t);
    m_priority(t);
  }
}

/* Calculate system load average */
/* load_avg = (59/60)*load_avg + (1/60)*ready_threads */
void 
calc_load_avg (void)
{
  ASSERT(thread_mlfqs);
  enum intr_level old_level = intr_disable ();
	
  struct fixed_point term1 = int_to_fixed(59);
  term1 = mult_fixed(term1, load_average);
  term1 = fixed_div_int(term1, 60);
  
  struct fixed_point term2 = int_to_fixed(list_size(&ready_list));
  if (thread_current () != idle_thread)
  {
    term2 = fixed_plus_int(term2, 1);
  }

  term2 = fixed_div_int(term2, 60);
  load_average = add_fixed(term1, term2);
  intr_set_level (old_level);
}

/* Calculate thread's recent CPU */
/* recent_cpu = (2*load_avg)/(2*load_avg + 1) * recent_cpu + nice  */
void 
calc_recent_cpu (struct thread *t)
{
  ASSERT(thread_mlfqs);

	if (t != idle_thread)
  {
    struct fixed_point term1 = fixed_mult_int(load_average, 2);
    struct fixed_point term2 = fixed_mult_int(load_average, 2);
    term2 = fixed_plus_int(term2, 1);
    term1 = div_fixed(term1, term2);
    term1 = fixed_mult_int(term1, t->recent_cpu);
    t->recent_cpu = fixed_to_int_roundInt(fixed_plus_int(term1, t->nice));
	}
}

/* Increment recent CPU */
void
increment_recent_cpu (void)
{
  ASSERT(thread_mlfqs);

	if (thread_current() != idle_thread)
  {
    int new_recent_cpu = thread_current ()->recent_cpu + 1;
		thread_current ()->recent_cpu = new_recent_cpu; 
	}
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  if (!thread_mlfqs) 
  {
    t->priority = priority;
    t->effective_priority = priority;
  }
  list_init (&t->donor_list);
  t->blocking_lock = NULL;
  t->magic = THREAD_MAGIC;
  sema_init(&(t->sleep_sema), 0);
  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
  t->nice = 0;
  t->recent_cpu = 0;
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
  {
    return idle_thread;
  }
  else
  {
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
  }
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

// Function for comparing wake-up times of two threads
static bool 
wake_up_less (const struct list_elem *thread1, const struct list_elem *thread2, void *aux UNUSED) 
{
  struct thread *t1 = list_entry(thread1, struct thread, sleep_elem);
  struct thread *t2 = list_entry(thread2, struct thread, sleep_elem);

  return ((t1->wake_up_time) < (t2->wake_up_time));
}

bool 
thread_priority_less (const struct list_elem *thread1, const struct list_elem *thread2, void *aux UNUSED) 
{
   struct thread *t1 = list_entry(thread1, struct thread, elem);
   struct thread *t2 = list_entry(thread2, struct thread, elem);

   return ((t2->effective_priority) < (t1->effective_priority));
}

void 
test_sleeping_thread (int64_t current_ticks) 
{
  struct list_elem *t_elem = list_begin(&sleep_list);
  while (t_elem != list_end(&sleep_list)) 
  {
    struct thread *t = list_entry(t_elem, struct thread, sleep_elem);
    if (current_ticks < t->wake_up_time)
    {
      break;
    }
    // If the wake_up_time of the thread at front of list is 
    // equal to the current number of OS ticks then it it time
    // to wake up the thread and remove if from the sleep list.
    list_remove(t_elem);
    sema_up(&(t->sleep_sema));
    t_elem = list_begin(&sleep_list);
  }
  verify_current_thread_highest();
}

void 
add_sleeping_thread (struct thread *current_t) 
{
  list_insert_ordered(&sleep_list, &current_t->sleep_elem, wake_up_less, NULL);
}

void 
add_thread_ready_priority_list (struct thread*t) 
{
  list_insert_ordered(&ready_list, &t->elem, thread_priority_less, NULL);
}

void 
add_thread_sema_priority_list (struct thread*t, struct semaphore*sema) 
{
    list_insert_ordered(&(sema->waiters), &t->elem, thread_priority_less, NULL);
}

void 
sort_thread_sema_priority_list (struct semaphore*sema) 
{
    list_sort(&(sema->waiters), thread_priority_less, NULL);
}

void
thread_priority_synchronize ()
{
  struct thread *cur_t = thread_current();
  cur_t->effective_priority = cur_t->priority;
  
  // First, check if the new priority is less than the priority of the thread's immediate donee (if one exists).
  //  If so, override the new priority with the donee's priority.
  if (!list_empty(&thread_current()->donor_list))
  {
    struct thread *cur_thread_donee = list_entry(list_front(&cur_t->donor_list), struct thread, donor_elem);

    if (cur_thread_donee->effective_priority > cur_t->effective_priority)
    {
      cur_t->effective_priority = cur_thread_donee->effective_priority;
    } 
  }

}

void 
verify_current_thread_highest () 
{
  struct thread *current_thread = thread_current();
  struct thread *next_thread_to_run = NULL;

  if (!list_empty(&ready_list))
  {
    next_thread_to_run = list_entry (list_front (&ready_list), struct thread, elem);
    if (intr_context())
    {
      ++thread_ticks;
      if ((current_thread->effective_priority < next_thread_to_run->effective_priority) || (thread_mlfqs && thread_ticks >= TIME_SLICE && current_thread->effective_priority == next_thread_to_run->effective_priority))
      {
        intr_yield_on_return(); 
      }
    }
    else
    {
      if (current_thread->effective_priority < next_thread_to_run->effective_priority)
      {
        thread_yield();
      }
    } 
  }
}

int returnLoadAverage(){
  return load_average.value;
}

/* Get thread by thread ID
   Necessary for updating variables for threads other than thread_current
   Returns null if tid doesn't exist in alL_list
*/
struct thread *get_thread(tid_t tid){
  struct list_elem *e;
  struct thread *found_thread = NULL;
  enum intr_level old_level;
  old_level = intr_disable ();

  for (e = list_begin (&all_list); e != list_end (&all_list); e = list_next (e)){
    struct thread *t = list_entry (e, struct thread, allelem);
    if (tid == t->tid){
      found_thread = t;
      break;
    }
  }

  intr_set_level (old_level);
  return found_thread;
}

/* Get child thread from child_list by thread ID
   Returns null if tid doesn't exist in current thread's child list
*/
struct thread *get_child(tid_t tid){
  struct list_elem *e;
  struct thread *t = thread_current();
  
  for (e = list_begin (&t->child_list); e != list_end (&t->child_list); e = list_next (e)){
    struct thread *child_thread = list_entry (e, struct thread, child_elem);
    if (child_thread->tid == tid){
      return child_thread;
    }
  }
  
  return NULL;
}

/* Initialize synchronization variables for thread.
   Used in thread_init and thread_create functions.
*/
void init_synchronization(struct thread *t){
  t->alive = true;
  t->parent_alive = true;
  t->waited = false;
  t->load_status = false;
  t->exit_status = -1;
  
  list_init(&t->child_list);
  sema_init(&t->wait_sema,0);
  sema_init(&t->load_sema,0);
 

  /* If current thread has initilized child list, insert child elem in list*/
  if (&thread_current()->child_list != NULL){
    list_push_back(&thread_current()->child_list, &t->child_elem);
  }
}
