#include "repl.h"

BOOL winrepl_start_keystone(winrepl_t *wr)
{
	if (wr->ks)
		return TRUE;

#ifdef _M_X64
	ks_arch arch = KS_ARCH_X86;
	ks_mode mode = KS_MODE_64;
#elif defined(_M_IX86)
	ks_arch arch = KS_ARCH_X86;
	ks_mode mode = KS_MODE_32;
#endif

	return ks_open(arch, mode, &wr->ks) == KS_ERR_OK;
}

static BOOL winrepl_create_debuggee(winrepl_t *wr)
{
	STARTUPINFO si = { 0 };
	TCHAR fileName[MAX_PATH] = { 0 };

	GetModuleFileName(NULL, fileName, MAX_PATH);

	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;	// already 0
	si.cb = sizeof(si);

	if (!CreateProcess(
		fileName,
		NULL,
		NULL,
		NULL,
		FALSE,
		DEBUG_ONLY_THIS_PROCESS,
		NULL,
		NULL,
		&si,
		&wr->procInfo
	))
	{
		return FALSE;
	}

	// swallow initial debug events
	while (TRUE)
	{
		DEBUG_EVENT dbg = { 0 };
		if (!WaitForDebugEvent(&dbg, 1000))
			break;

		if (dbg.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
			CloseHandle(dbg.u.CreateProcessInfo.hFile);
	
		if (dbg.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
			dbg.dwThreadId == wr->procInfo.dwThreadId)
			break;

		ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, DBG_CONTINUE);
	}

	return TRUE;
}

static BOOL winrepl_alloc_mem(winrepl_t *wr)
{
	if (wr->nMemSize == 0)
		wr->nMemSize = WINREPL_INIT_MEM_SIZE;

	wr->lpStartAddress = VirtualAllocEx(
		wr->procInfo.hProcess,
		NULL,
		wr->nMemSize,
		MEM_COMMIT,
		PAGE_EXECUTE_READ);

	return wr->lpStartAddress != NULL;
}

static BOOL winrepl_reset_context(winrepl_t *wr)
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(wr->procInfo.hThread, &ctx))
		return FALSE;

#ifdef _M_X64
	ctx.Rip = (DWORD64)wr->lpStartAddress;

	ctx.Rax = 0;
	ctx.Rbx = 0;
	ctx.Rcx = 0;
	ctx.Rdx = 0;

	ctx.Rsi = 0;
	ctx.Rdi = 0;
	ctx.Rbp = 0;

	ctx.R8 = 0;
	ctx.R9 = 0;
	ctx.R10 = 0;
	ctx.R11 = 0;
	ctx.R12 = 0;
	ctx.R13 = 0;
	ctx.R14 = 0;
	ctx.R15 = 0;

	ctx.EFlags = 0;
#elif defined(_M_IX86)
	ctx.Eip = (DWORD)ctx.Eip;

	ctx.Eax = 0;
	ctx.Ebx = 0;
	ctx.Ecx = 0;
	ctx.Edx = 0;
	
	ctx.Esi = 0;
	ctx.Edi = 0;
	ctx.Ebp = 0;

	ctx.EFlags = 0;
#elif defined(_M_ARM)
	// todo: ARM?
	return FALSE;
#else
	return FALSE;
#endif

	wr->prev = ctx;

	return SetThreadContext(wr->procInfo.hThread, &ctx);
}

BOOL winrepl_init(winrepl_t *wr)
{
	if (!winrepl_start_keystone(wr))
		return FALSE;

	if (!winrepl_create_debuggee(wr))
		return FALSE;

	if (!winrepl_alloc_mem(wr))
		return FALSE;

	if (!winrepl_reset_context(wr))
		return FALSE;

	return TRUE;
}