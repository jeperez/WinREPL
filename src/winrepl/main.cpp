#include "repl.h"

static winrepl_t wr = { 0 };

BOOL CALLBACK winrepl_exit(DWORD dwCtrlCode)
{
	DebugActiveProcessStop(wr.procInfo.dwProcessId);
	ExitProcess(0);
}

int main(int argc, char *argv[])
{
	SetConsoleCtrlHandler(winrepl_exit, TRUE);

	std::cout << "WinREPL v0.1 by @zerosum0x0\n";
	std::cout << "Input assembly mnemonics, or \".help\" for a list of commands.\n" << std::endl;

	while (TRUE)
	{	
		if (!winrepl_loop(&wr))
			break;
	}

	return 0;
}