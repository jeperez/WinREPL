#include "repl.h"


std::string winrepl_read()
{
	std::string command;

	std::cout << ">>> ";
	std::getline(std::cin, command);

	trim(command);

	return command;
}