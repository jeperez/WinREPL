#include "repl.h"
#include <stdio.h>

static inline BOOL check_bit(DWORD var, char pos)
{
	return !!((var) & (1 << (pos)));
}

void winrepl_print_assembly(unsigned char *encode, size_t size)
{
	printf("assembled (%zu bytes): ", size);
	
	for (size_t i = 0; i < size; ++i)
		printf("%02x ", encode[i]);

	printf("\n");
}

static void winrepl_reset_console_color()
{
	static HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

static void winrepl_print_console_color(WORD attributes, const char *format, ...)
{
	static HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	if (attributes != 0)
		SetConsoleTextAttribute(hConsole, attributes);
	
	va_list argptr;
	va_start(argptr, format);
	vfprintf(stderr, format, argptr);
	va_end(argptr);

	winrepl_reset_console_color();
}


static void winrepl_print_register_32(const char *reg, DWORD64 value, DWORD64 prev)
{
	winrepl_print_console_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY, "%s: ", reg);

	WORD color = (prev == value) ? 0 : FOREGROUND_RED | FOREGROUND_INTENSITY;
	winrepl_print_console_color(color, "%08llx ", value);
}

static void winrepl_print_register_64(const char *reg, DWORD64 value, DWORD64 prev)
{
	winrepl_print_console_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY, "%s: ", reg);

	WORD color = (prev == value) ? 0 : FOREGROUND_RED | FOREGROUND_INTENSITY;
	winrepl_print_console_color(color, "%016llx ", value);
}


static void winrepl_print_register_flag(const char *flag, BOOL value, BOOL prev)
{
	winrepl_print_console_color(FOREGROUND_BLUE | FOREGROUND_GREEN, "%s: ", flag);

	WORD color = (prev == value) ? 0 : FOREGROUND_RED | FOREGROUND_INTENSITY;
	winrepl_print_console_color(color, "%d  ", value);
}

#ifdef _M_X64
static void winrepl_print_register_xmm(const char *reg, M128A value, M128A prev)
{

	winrepl_print_console_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY, "%s: ", reg);

	printf("{ ");
	WORD color = (prev.High == value.High) ? 0 : FOREGROUND_RED | FOREGROUND_INTENSITY;
	winrepl_print_console_color(color, "%10.10e", value.High);

	printf(", ");

	color = (prev.Low == value.Low) ? 0 : FOREGROUND_RED | FOREGROUND_INTENSITY;
	winrepl_print_console_color(color, "%10.10e", value.Low);


	printf(" }\t");

	color = (prev.High == value.High) ? 0 : FOREGROUND_RED | FOREGROUND_INTENSITY;
	winrepl_print_console_color(color, "%016llx", value.High);

	color = (prev.Low == value.Low) ? 0 : FOREGROUND_RED | FOREGROUND_INTENSITY;
	winrepl_print_console_color(color, "%016llx", value.Low);

	printf("\n");

}
#elif defined(_M_IX86)
// ??????????????
static void winrepl_print_register_xmm(const char *reg, int a, int b)
{}
#else
// ?!!!!!!!!!
static void winrepl_print_register_xmm(const char *reg, int a, int b)
{}
#endif


void winrepl_print_error(const char *format, ...)
{
	static HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	winrepl_print_console_color(FOREGROUND_RED | FOREGROUND_INTENSITY, "%s", "[-] ");

	va_list argptr;
	va_start(argptr, format);
	vfprintf(stderr, format, argptr);
	va_end(argptr);

	DWORD dwErr = GetLastError();
	if (dwErr != 0)
		printf(" (errno: %d)", dwErr);

	printf("\n");
}

void winrepl_print_bytes(unsigned char *addr, int len, unsigned long long start_addr)
{
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	for (i = 0; i < len; i++)
	{
		if ((i % 16) == 0)
		{
			if (i != 0)
				printf("  %s\n", buff);

			printf("  %04llx ", start_addr + i);
		}

		printf(" %02x", pc[i]);

		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	while ((i % 16) != 0)
	{
		printf("   ");
		++i;
	}

	printf("  %s\n", buff);
}

void winrepl_print_good(const char *format, ...)
{
	winrepl_print_console_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY, "%s", "[+] ");
	va_list argptr;
	va_start(argptr, format);
	vfprintf(stderr, format, argptr);
	va_end(argptr);
	printf("\n");
}

void winrepl_print_registers(winrepl_t *wr)
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	GetThreadContext(wr->procInfo.hThread, &ctx);

#ifdef _M_X64
	winrepl_print_register_64("rax", ctx.Rax, wr->prev.Rax);
	winrepl_print_register_64("rbx", ctx.Rbx, wr->prev.Rbx);
	winrepl_print_register_64("rcx", ctx.Rcx, wr->prev.Rcx);
	winrepl_print_register_64("rdx", ctx.Rdx, wr->prev.Rdx);
	printf("\n");

	winrepl_print_register_64("r8 ", ctx.R8, wr->prev.R8);
	winrepl_print_register_64("r9 ", ctx.R9, wr->prev.R9);
	winrepl_print_register_64("r10", ctx.R10, wr->prev.R10);
	winrepl_print_register_64("r11", ctx.R11, wr->prev.R11);
	printf("\n");

	winrepl_print_register_64("r12", ctx.R12, wr->prev.R12);
	winrepl_print_register_64("r13", ctx.R13, wr->prev.R13);
	winrepl_print_register_64("r14", ctx.R14, wr->prev.R14);
	winrepl_print_register_64("r15", ctx.R15, wr->prev.R15);
	printf("\n");

	
	winrepl_print_register_64("rsi", ctx.Rsi, wr->prev.Rsi);
	winrepl_print_register_64("rdi", ctx.Rdi, wr->prev.Rdi);
	printf("\n");

	winrepl_print_register_64("rip", ctx.Rip, wr->prev.Rip);
	winrepl_print_register_64("rsp", ctx.Rsp, wr->prev.Rsp);
	winrepl_print_register_64("rbp", ctx.Rbp, wr->prev.Rbp);
	printf("\n");
#elif defined(_M_IX86)
	winrepl_print_register_32("eax", ctx.Eax, wr->prev.Eax);
	winrepl_print_register_32("ebx", ctx.Ebx, wr->prev.Ebx);
	winrepl_print_register_32("ecx", ctx.Ecx, wr->prev.Ecx);
	winrepl_print_register_32("edx", ctx.Edx, wr->prev.Edx);
	printf("\n");

	winrepl_print_register_32("esi", ctx.Esi, wr->prev.Esi);
	winrepl_print_register_32("edi", ctx.Edi, wr->prev.Edi);
	printf("\n");

	winrepl_print_register_32("eip", ctx.Eip, wr->prev.Eip);
	winrepl_print_register_32("esp", ctx.Esp, wr->prev.Esp);
	winrepl_print_register_32("ebp", ctx.Ebp, wr->prev.Ebp);
	printf("\n");
#endif

#if defined(_M_X64) || defined(_M_IX86)
	printf("flags: %08x ", ctx.EFlags);

	winrepl_print_register_flag("CF", check_bit(ctx.EFlags, 0), check_bit(wr->prev.EFlags, 0));
	winrepl_print_register_flag("PF", check_bit(ctx.EFlags, 2), check_bit(wr->prev.EFlags, 2));
	winrepl_print_register_flag("AF", check_bit(ctx.EFlags, 3), check_bit(wr->prev.EFlags, 3));
	winrepl_print_register_flag("ZF", check_bit(ctx.EFlags, 6), check_bit(wr->prev.EFlags, 6));
	winrepl_print_register_flag("SF", check_bit(ctx.EFlags, 7), check_bit(wr->prev.EFlags, 7));
	winrepl_print_register_flag("DF", check_bit(ctx.EFlags, 10), check_bit(wr->prev.EFlags, 10));
	winrepl_print_register_flag("OF", check_bit(ctx.EFlags, 11), check_bit(wr->prev.EFlags, 11));

	/*

	printf("cf: %d, ", check_bit(ctx.EFlags, 0));
	printf("pf: %d, ", check_bit(ctx.EFlags, 2));
	printf("af: %d, ", check_bit(ctx.EFlags, 4));
	printf("zf: %d, ", check_bit(ctx.EFlags, 6));
	printf("sf: %d, ", check_bit(ctx.EFlags, 7));
	printf("df: %d, ", check_bit(ctx.EFlags, 10));
	printf("of: %d]", check_bit(ctx.EFlags, 11));
	*/
	printf("\n");
#endif
}

void winrepl_print_registers_all(winrepl_t *wr)
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	GetThreadContext(wr->procInfo.hThread, &ctx);

#ifdef _M_X64
	winrepl_print_register_xmm("xmm0 ", ctx.Xmm0, wr->prev.Xmm0);
	winrepl_print_register_xmm("xmm1 ", ctx.Xmm1, wr->prev.Xmm1);
	winrepl_print_register_xmm("xmm2 ", ctx.Xmm2, wr->prev.Xmm2);
	winrepl_print_register_xmm("xmm3 ", ctx.Xmm3, wr->prev.Xmm3);
	winrepl_print_register_xmm("xmm4 ", ctx.Xmm4, wr->prev.Xmm4);
	winrepl_print_register_xmm("xmm5 ", ctx.Xmm5, wr->prev.Xmm5);
	winrepl_print_register_xmm("xmm6 ", ctx.Xmm6, wr->prev.Xmm6);
	winrepl_print_register_xmm("xmm7 ", ctx.Xmm7, wr->prev.Xmm7);
	winrepl_print_register_xmm("xmm8 ", ctx.Xmm8, wr->prev.Xmm8);
	winrepl_print_register_xmm("xmm9 ", ctx.Xmm9, wr->prev.Xmm9);
	winrepl_print_register_xmm("xmm10", ctx.Xmm10, wr->prev.Xmm10);
	winrepl_print_register_xmm("xmm11", ctx.Xmm11, wr->prev.Xmm11);
	winrepl_print_register_xmm("xmm12", ctx.Xmm12, wr->prev.Xmm12);
	winrepl_print_register_xmm("xmm13", ctx.Xmm13, wr->prev.Xmm13);
	winrepl_print_register_xmm("xmm14", ctx.Xmm14, wr->prev.Xmm14);
	winrepl_print_register_xmm("xmm15", ctx.Xmm15, wr->prev.Xmm15);
#endif

	winrepl_print_registers(wr);
}

void winrepl_print_pids(winrepl_t *wr)
{
	DWORD dwPPID = GetCurrentProcessId();
	DWORD dwPTID = GetCurrentThreadId();
	DWORD dwCPID = wr->procInfo.dwProcessId;
	DWORD dwCTID = wr->procInfo.dwThreadId;
	printf("PPID: %d\tPTID: %d\tCPID: %d\tCTID: %d\n", dwPPID, dwPTID, dwCPID, dwCTID);
}