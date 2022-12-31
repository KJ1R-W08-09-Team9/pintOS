#include "userprog/syscall.h"
// #include <user/syscall.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/* ---------- Project 2 ---------- */
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "kernel/stdio.h"
#include "threads/palloc.h"
#include "threads/init.h"
/* ------------------------------- */

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* system call foward declaration */
void halt(void);
void exit(int);
bool create(const char *, unsigned);
bool remove(const char *);
int write(int, const void *, unsigned);
int open(const char *);
int add_to_fdt(struct file *);
struct file *fd_to_struct_filep(int);
int filesize(int);
int read(int, void *, unsigned);
int write(int, const void *, unsigned);
void seek(int, unsigned);
unsigned tell(int);
void close(int);
tid_t fork(const char *, struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	/* Project 2 filesys lock init */
	lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.

	/* Projects 2 and later. */
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		memcpy(&thread_current()->ptf, f, sizeof(struct intr_frame));
		f->R.rax = fork(f->R.rdi, f);
		break;
	case SYS_EXEC:
		exec(f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	default:
		exit(-1);
		break;
	}
}

/* 주소 값이 유저 영역 주소 값인지 확인하고, 유저 영역을 벗어난 영역일 경우 프로세스 종료 exit(-1)*/
void check_address(void *addr)
{
	struct thread *curr = thread_current();
	if (addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(curr->pml4, addr) == NULL)
	{
		exit(-1);
	}
}

/* pintOS를 종료 */
void halt(void)
{
	power_off();
}

/* 현재 프로세스를 종료
 정상적으로 종료됐다면 status : 0
 아니면 0이 아닌 숫자 */
void exit(int status)
{
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

bool create(const char *file, unsigned initial_size)
{
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

tid_t fork(const char *thread_name, struct intr_frame *f)
{
	check_address(thread_name);
	return process_fork(thread_name, &thread_current()->ptf);
}

/* 자식프로세스를 생성하고 프로그램을 실행시킴 */
int exec(const char *file)
{
	check_address(file);

	int file_size = strlen(file) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if (!fn_copy)
	{
		exit(-1);
		return -1;
	}
	strlcpy(fn_copy, file, file_size);
	if (process_exec(fn_copy) == -1)
	{
		exit(-1);
		return -1;
	}
}

/* 자식 프로세스가 수행되고 종료될 때 까지 부모 프로세스 대기 */
int wait(tid_t tid)
{
	return process_wait(tid);
}

void close(int fd)
{
	if (fd < 2 || fd >= FDCOUNT_LIMIT)
		return;

	struct file *file = fd_to_struct_filep(fd);
	if (file == NULL)
		return;

	lock_acquire(&filesys_lock);
	thread_current()->file_descriptor_table[fd] = NULL;
	file_close(file);
	lock_release(&filesys_lock);
}

int open(const char *file)
{
	check_address(file);
	struct file *file_object;
	file_object = filesys_open(file);

	if (file_object == NULL)
		return -1;

	int fd_index = add_to_fdt(file_object);

	if (fd_index == -1)
		file_close(file_object);

	return fd_index;
}

/*
현재 프로세스의 fdt에 file을 추가
fdt가 차 있을 경우 idx + 1
fdt에 추가가 불가능하면 -1
추가 가능하다면 해당 file descriptor index 반환
*/
int add_to_fdt(struct file *file)
{
	struct thread *curr = thread_current();
	struct file **fdt = curr->file_descriptor_table;
	int index = curr->fd_index;

	while (fdt[index] != NULL && index < FDCOUNT_LIMIT)
		index++;

	if (FDCOUNT_LIMIT <= index)
		return -1;

	curr->fd_index = index;
	fdt[index] = file;
	return index;
}

/* fd 값을 넣으면 file 주소를 반환하는 함수 */
struct file *fd_to_struct_filep(int fd)
{
	if (fd < 0 || fd > FDCOUNT_LIMIT)
		return NULL;

	struct thread *curr = thread_current();
	struct file **fdt = curr->file_descriptor_table;

	struct file *file = fdt[fd];
	return file;
}

/* file 크기를 반환하는 함수 */
int filesize(int fd)
{
	struct file *file = fd_to_struct_filep(fd);
	if (file == NULL)
		return -1;

	return file_length(file);
}

/* file을 읽는 함수 */
int read(int fd, void *buffer, unsigned size)
{
	/* 버퍼와 버퍼의 끝 영역에 대한 주소 유효성 체크 */
	check_address(buffer);
	unsigned char *temp_buff = buffer;
	struct file *file_obj = fd_to_struct_filep(fd);
	int result_size;

	if (file_obj == NULL)
		return -1;

	/* case1 : STDIN (= 0) */
	if (fd == STDIN_FILENO)
	{
		lock_acquire(&filesys_lock);
		int cnt;
		for (cnt = 0; cnt < size; cnt++)
		{
			char c = input_getc();
			*temp_buff = c;
			temp_buff++;
			if (c == '\0')
				break;
		}
		lock_release(&filesys_lock);
		result_size = cnt;
	}
	/* case2 : STOUT */
	else if (fd == STDOUT_FILENO)
	{
		return -1;
	}
	/* case3 : other */
	else
	{
		lock_acquire(&filesys_lock);
		result_size = file_read(file_obj, buffer, size);
		lock_release(&filesys_lock);
	}
	return result_size;
}

int write(int fd, const void *buffer, unsigned size)
{
	check_address(buffer);
	if (fd == 0)
		return -1;

	int write_result_size;
	struct file *file_obj = fd_to_struct_filep(fd);

	/* fd = STDOUT = 1 */
	if (fd == 1)
	{
		lock_acquire(&filesys_lock);
		putbuf(buffer, size); /* to print buffer strings on the display*/
		lock_release(&filesys_lock);
		write_result_size = size;
	}
	/* other file fd */
	else
	{
		if (file_obj == NULL)
		{
			write_result_size = -1;
		}
		else
		{
			lock_acquire(&filesys_lock);
			write_result_size = file_write(file_obj, buffer, size);
			lock_release(&filesys_lock);
		}
	}

	return write_result_size;
}

/* fd 가 가리키고 있는 file의 pos을 new positon으로 변경한다. */
void seek(int fd, unsigned position)
{
	struct file *file = fd_to_struct_filep(fd);

	if (file == NULL)
		return;

	file_seek(file, position);
}

/* fd가 가리키고 있는 file의 pos을 반환한다. */
unsigned tell(int fd)
{
	struct file *file = fd_to_struct_filep(fd);

	if (file == NULL)
		return;

	return (int)file_tell(file);
}
