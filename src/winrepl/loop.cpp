#include <Windows.h>

#include <string>
#include <vector>
#include "repl.h"

BOOL winrepl_loop(winrepl_t *wr)
{
	if (!winrepl_init(wr))
		return FALSE;

	winrepl_print_pids(wr);
	winrepl_print_registers(wr);

	while (TRUE)
	{
		std::string command = winrepl_read();

		if (command.size() == 0)
			continue;

		if (!winrepl_eval(wr, command))
		{
			winrepl_print_error("An unrecoverable error occurred, resetting environment!");
			break;
		}
	}

	return TRUE;
}