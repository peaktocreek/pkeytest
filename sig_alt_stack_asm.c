// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#define __SANE_USERSPACE_TYPES__
#include <errno.h>
#include <linux/elf.h>
#include <linux/futex.h>
#include <time.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <setjmp.h>
#include <linux/types.h>

/*
 * need those definition for manually build using gcc.
 * gcc -mxsave  -o sig_alt_stack_asm -O2 -g -std=gnu99 -pthread -Wall sig_alt_stack_asm.c -lrt -ldl -lm
 */

#ifndef u16
#define u16 __u16
#endif

#ifndef u32
#define u32 __u32
#endif

#ifndef u64
#define u64 __u64
#endif

int sigaltstack_size = 2 * 1024 * 1024;
void * altstack_addr;
int g_pkey;

void asm_handler(int signum, siginfo_t *si, void *vucontext);

__asm__(
	".global asm_handle\n"
	"asm_handler:\n"
	"	mov %rdx, %r8\n"
	"	xor %eax, %eax\n"
	"	xor %ecx, %ecx\n"
	"	xor %edx, %edx\n"
	"	wrpkru\n"
	"	mov %r8, %rdx\n"
	"	call inner\n"
	"	ret\n"
);

static inline u32 read_pkru(void)
{
	unsigned int eax, edx;
	unsigned int ecx = 0;
	unsigned pkey_reg;

	asm volatile(".byte 0x0f,0x01,0xee\n\t"
		     : "=a" (eax), "=d" (edx)
		     : "c" (ecx));
	pkey_reg = eax;
	return pkey_reg;
}

static inline void write_pkru(u64 pkey_reg)
{
	unsigned int eax = pkey_reg;
	unsigned int ecx = 0;
	unsigned int edx = 0;

	asm volatile(".byte 0x0f,0x01,0xef\n\t"
		     : : "a" (eax), "c" (ecx), "d" (edx));
}

void inner(int signum, siginfo_t *si, void *ptr)
{
	printf("inner:ctx%p\n", ptr);
	ucontext_t * ctx = (ucontext_t *) ptr;
	assert(ctx->uc_stack.ss_sp == altstack_addr);
}

void setup_address_with_pkey(int size, int *pkeyOut,
					  void **ptrOut)
{
	int pkey;
	void *ptr;
	int ret;

	pkey = pkey_alloc(0, 0);
	assert(pkey > 0);

	ptr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	assert(ptr != (void*) -1);
	altstack_addr = ptr;

	ret = pkey_mprotect((void *)ptr, size, PROT_READ | PROT_WRITE, pkey);
	assert(!ret);

	*pkeyOut = pkey;
	*ptrOut = ptr;
}

void setup_sigusr1()
{
	void * ptr;
	stack_t altstack;

	setup_address_with_pkey(sigaltstack_size, &g_pkey, &ptr);
	printf("use pkey=%x\n", g_pkey);

	altstack.ss_sp = ptr;
	assert(altstack.ss_sp != 0);

	printf("pkey=%d, ss_flags=%x\n", g_pkey, altstack.ss_flags);

	altstack.ss_flags = 0;
	altstack.ss_size = sigaltstack_size;

	int ret = sigaltstack(&altstack, NULL);
	assert(ret == 0);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = 0;
	sa.sa_sigaction = asm_handler;
	sa.sa_flags = SA_ONSTACK | SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	ret = sigaction(SIGUSR1, &sa, NULL);
	assert(ret == 0);
}

void test_sigaltstack_pkey_with_rw_permission()
{
	int pkru_orig, pkru;
	int status;

	write_pkru(0x55555554);
	setup_sigusr1();

	status = pkey_set(g_pkey, 0);
	assert(!status);

	pkru_orig = read_pkru();
	printf("PKRU(before):%x, pid:%d\n", pkru_orig, getpid());

	int ret = raise(SIGUSR1);
        assert(ret == 0);

	pkru = read_pkru();
	printf("PKRU(after):%x, pid:%d\n", pkru, getpid());

        assert(pkru_orig == pkru);
}

void test_sigaltstack_pkey_with_ro_permission()
{
	int pkru_orig, pkru;
	int status;

	write_pkru(0x55555554);
	setup_sigusr1();

	status = pkey_set(g_pkey, PKEY_DISABLE_WRITE);
	assert(!status);

	pkru_orig = read_pkru();
	printf("PKRU(before):%x, pid:%d\n", pkru_orig, getpid());

	int ret = raise(SIGUSR1);
        assert(ret == 0);

	pkru = read_pkru();
	printf("PKRU(after):%x, pid:%d\n", pkru, getpid());

        assert(pkru_orig == pkru);
}

void test_sigaltstack_pkey_with_no_permission()
{
	int pkru_orig, pkru;
	int status;

	write_pkru(0x55555554);
	setup_sigusr1();

	status = pkey_set(g_pkey, PKEY_DISABLE_ACCESS);
	assert(!status);

	pkru_orig = read_pkru();
	printf("PKRU(before):%x, pid:%d\n", pkru_orig, getpid());

	int ret = raise(SIGUSR1);
        assert(ret == 0);

	pkru = read_pkru();
	printf("PKRU(after):%x, pid:%d\n", pkru, getpid());

        assert(pkru_orig == pkru);
}

int main(void)
{
	test_sigaltstack_pkey_with_rw_permission();
	test_sigaltstack_pkey_with_ro_permission();
	test_sigaltstack_pkey_with_no_permission();
	
	return 0;
}
