#pragma once

#include <iostream>

#include <Windows.h>
#include <keystone/keystone.h>

#include "str.h"

#define WINREPL_INIT_MEM_SIZE 0x10000

typedef struct _winrepl_context_t
{
	PROCESS_INFORMATION procInfo;
	LPVOID lpStartAddress;
	SIZE_T nMemSize;
	ks_engine *ks;
	CONTEXT prev;
	CONTEXT curr;
} winrepl_t;

BOOL winrepl_init(winrepl_t *wr);
BOOL winrepl_loop(winrepl_t *wr); 

std::string winrepl_read();

BOOL winrepl_eval(winrepl_t *wr, std::string command);
BOOL winrepl_write_shellcode(winrepl_t *wr, unsigned char *encode, size_t size);
void winrepl_debug_shellcode(winrepl_t *wr);

BOOL winrepl_run_command(winrepl_t *wr, std::string command);

void winrepl_print_pids(winrepl_t *wr);
void winrepl_print_registers(winrepl_t *wr);
void winrepl_print_registers_all(winrepl_t *wr);
void winrepl_print_assembly(unsigned char *encode, size_t size);
void winrepl_print_bytes(unsigned char *addr, int len, unsigned long long start_addr = 0);
void winrepl_print_good(const char *format, ...);
void winrepl_print_error(const char *format, ...);

