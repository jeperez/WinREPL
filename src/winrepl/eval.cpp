#include "repl.h"

static void winrepl_fix_rip(winrepl_t *wr)
{
	// fix RIP becasue of \xcc
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(wr->procInfo.hThread, &ctx);

#ifdef _M_X64
	ctx.Rip = ctx.Rip - 1;
#elif defined(_M_IX86)
	ctx.Eip = ctx.Eip - 1;
#endif
	SetThreadContext(wr->procInfo.hThread, &ctx);
}

BOOL winrepl_write_shellcode(winrepl_t *wr, unsigned char *encode, size_t size)
{
	DWORD dwOldProtect = 0;
	SIZE_T nBytes;
	CONTEXT ctx = { 0 };

	winrepl_print_assembly(encode, size);

	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(wr->procInfo.hThread, &ctx))
		return FALSE;


#ifdef _M_X64
	LPVOID addr = (LPVOID)ctx.Rip;
#elif defined(_M_IX86)
	LPVOID addr = (LPVOID)ctx.Eip;
#endif

	if (!VirtualProtectEx(wr->procInfo.hProcess, (LPVOID)addr, size, PAGE_READWRITE, &dwOldProtect))
		return FALSE;

	if (!WriteProcessMemory(wr->procInfo.hProcess, (LPVOID)addr, (LPCVOID)encode, size, &nBytes))
		return FALSE;

	if (!WriteProcessMemory(wr->procInfo.hProcess, (LPVOID)((LPBYTE)addr + size), (LPCVOID)"\xcc", 1, &nBytes))
		return FALSE;

	if (!VirtualProtectEx(wr->procInfo.hProcess, (LPVOID)addr, size, dwOldProtect, &dwOldProtect))
		return FALSE;

	FlushInstructionCache(wr->procInfo.hProcess, (LPCVOID)addr, size + 1);

	return TRUE;
}

void winrepl_debug_shellcode(winrepl_t *wr)
{
	BOOL go = TRUE;
	while (go)
	{
		ContinueDebugEvent(wr->procInfo.dwProcessId, wr->procInfo.dwThreadId, DBG_CONTINUE);

		DEBUG_EVENT dbg = { 0 };
		if (!WaitForDebugEvent(&dbg, INFINITE))
			break;

		if (dbg.dwThreadId != wr->procInfo.dwThreadId)
		{
			ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, DBG_CONTINUE);
			continue;
		}

		if (dbg.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && dbg.dwThreadId == wr->procInfo.dwThreadId)
		{
			go = FALSE;

			switch (dbg.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_ACCESS_VIOLATION:
				break;

			case EXCEPTION_PRIV_INSTRUCTION:
				break;

			case EXCEPTION_BREAKPOINT:
				break;
			default:
				break;
			}
		}
	}

	winrepl_fix_rip(wr);

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(wr->procInfo.hThread, &ctx);

	memcpy(&wr->prev, &wr->curr, sizeof(CONTEXT));
	memcpy(&wr->curr, &ctx, sizeof(CONTEXT));

	winrepl_print_registers(wr);
}


static BOOL winrepl_run_shellcode(winrepl_t *wr, std::string assembly)
{
	size_t count;
	unsigned char *encode;
	size_t size;

	if (ks_asm(wr->ks, assembly.c_str(), 0, &encode, &size, &count) != KS_ERR_OK)
	{
		printf("ERROR: ks_asm() failed & count = %zu, error = %u\n", count, ks_errno(wr->ks));
		return TRUE;
	}

	if (!winrepl_write_shellcode(wr, encode, size))
		return FALSE;

	ks_free(encode);

	winrepl_debug_shellcode(wr);

	return TRUE;
}

BOOL winrepl_eval(winrepl_t *wr, std::string command)
{
	try
	{
		if (command.at(0) == '.')
			return winrepl_run_command(wr, command);

		return winrepl_run_shellcode(wr, command);
	}
	catch (...)
	{
		winrepl_print_error("An unhandled C++ exception occurred.");
	}

	return TRUE;
}