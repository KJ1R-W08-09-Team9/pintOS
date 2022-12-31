#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define	STDIN_FILENO	0
#define	STDOUT_FILENO	1

void syscall_init (void);

/* Project 2 관련 추가  */

struct lock filesys_lock;
/* 주소 값이 유저 영역 주소 값인지 확인하고, 유저 영역을 벗어난 영역일 경우 프로세스 종료 exit(-1)*/
void check_address(void *);

/* 시스템 콜 인자를 커널에 복사, 스택포인터(rsp)에 count 만큼의 데이터를 arg에 저장 */
void get_argument(void *, int *, int );


#endif /* userprog/syscall.h */
