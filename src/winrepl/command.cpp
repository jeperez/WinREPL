#include "repl.h"


static BOOL winrepl_command_kernel32(winrepl_t *wr, std::vector<std::string> parts)
{
	do
	{
		if (parts.size() != 1)
		{
			winrepl_print_error("Usage: .kernel32 func");
			break;
		}

		HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
		FARPROC addr = GetProcAddress(kernel32, parts[0].c_str());

		if (!addr)
		{
			winrepl_print_error("Unable to find that export!");
			break;
		}

		winrepl_print_good("Kernel32.dll at %p, export located at %p", (LPVOID)kernel32, (LPVOID)addr);

	} while (0);

	return TRUE;
}

static BOOL winrepl_command_shellcode(winrepl_t *wr, std::vector<std::string> parts)
{
	do
	{
		std::string fixed = join(parts, "");
		std::string bin_str = from_hex(std::begin(fixed), std::end(fixed));
		std::vector<std::uint8_t> bytes(std::begin(bin_str), std::end(bin_str));

		if (bytes.size() == 0)
		{
			winrepl_print_error("Usage: .shellcode hexdata");
			break;
		}

		if (!winrepl_write_shellcode(wr, &bytes[0], bytes.size()))
		{
			winrepl_print_error("Unable to allocate shellcode!");
			return TRUE;
		}

		winrepl_debug_shellcode(wr);

	} while (0);

	return TRUE;
}

static BOOL winrepl_command_peb(winrepl_t *wr, std::vector<std::string> parts)
{
#ifdef _M_X64
	// xor eax, eax
	// mov rax, gs:[eax+0x60]
	unsigned char bytes[] = { 0x31, 0xc0, 0x65, 0x48, 0x8b, 0x40, 0x60 };
#elif defined(_M_IX86)
	// xor eax, eax
	// mov eax, fs:[eax+0x30]
	unsigned char bytes[] = { 0x31, 0xC0, 0x64, 0x8B, 0x40, 0x30 };
#endif
	if (!winrepl_write_shellcode(wr, bytes, sizeof(bytes)))
	{
		winrepl_print_error("Unable to allocate shellcode!");
		return TRUE;
	}

	winrepl_debug_shellcode(wr);

	return TRUE;
}

static BOOL winrepl_command_allocate(winrepl_t *wr, std::vector<std::string> parts)
{
	do
	{
		if (parts.size() != 1)
		{
			winrepl_print_error("Usage: .allocate size");
			break;
		}

		size_t size = atol(parts[0].c_str());

		if (size == 0)
		{
			winrepl_print_error("Usage: .allocate size");
			break;
		}

		LPVOID addr = VirtualAllocEx(
			wr->procInfo.hProcess,
			NULL,
			size,
			MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		);

		if (!addr)
		{
			winrepl_print_error("Unable to allocate memory!");
			break;
		}

		winrepl_print_good("Allocated RWX memory at %p (size: %d)", addr, size);
	} while (0);

	return TRUE;
}

static BOOL winrepl_command_write(winrepl_t *wr, std::vector<std::string> parts)
{

	do
	{
		if (parts.size() < 2)
		{
			winrepl_print_error("Usage: .write addr hexdata");
			break;
		}
		
		
		unsigned long long x = 0;
		std::istringstream iss(parts[0]);
		iss >> std::hex >> x;
		parts.erase(parts.begin());

		std::string fixed = join(parts, "");
		//separate<2, ' '>(fixed);
		std::string bin_str = from_hex(std::begin(fixed), std::end(fixed));
		std::vector<std::uint8_t> bytes(std::begin(bin_str), std::end(bin_str));

		if (x == 0 || bytes.size() == 0)
		{
			winrepl_print_error("Usage: .write addr hexdata");
			break;
		}

		SIZE_T nBytes;

		if (!WriteProcessMemory(
			wr->procInfo.hProcess,
			(LPVOID)x,
			&bytes[0],
			bytes.size(),
			&nBytes
		))
		{
			winrepl_print_error("Unable to write hex data!");
			break;
		}

		winrepl_print_good("Wrote %d bytes to %p", nBytes, (LPVOID)x);
		winrepl_print_bytes(&bytes[0], (int)bytes.size(), x);

	} while (0);


	return TRUE;
}

static BOOL winrepl_command_read(winrepl_t *wr, std::vector<std::string> parts)
{
	do
	{
		if (parts.size() != 2)
		{
			winrepl_print_error("Usage: .read addr size");
			break;
		}

		size_t size = atol(parts[1].c_str());
		
		unsigned long long x = 0;
		std::istringstream iss(parts[0]);
		iss >> std::hex >> x;

		if (size == 0 || x == 0)
		{
			winrepl_print_error("Usage: .read addr size");
			break;
		}

		std::vector<unsigned char> bytes;
		bytes.reserve(size);

		SIZE_T nBytes;

		if (!ReadProcessMemory(
			wr->procInfo.hProcess,
			(LPCVOID)x,
			&bytes[0],
			size,
			&nBytes
		))
		{
			winrepl_print_error("Unable to read from address: %p!", (LPVOID)x);
			break;
		}

		winrepl_print_bytes(&bytes[0], (int)nBytes, x);

	} while (0);

	return TRUE;
}

static BOOL winrepl_command_loadlibrary(winrepl_t *wr, std::vector<std::string> parts)
{
	do
	{
		if (parts.size() < 1)
		{
			winrepl_print_error("The path is missing!");
			break;
		}

		std::string dll = join(parts, "");

		LPVOID pStr = VirtualAllocEx(
			wr->procInfo.hProcess,
			NULL,
			dll.length() + 1,
			MEM_COMMIT,
			PAGE_READWRITE);

		if (!pStr)
		{
			winrepl_print_error("Unable to allocate DLL path!");
			break;
		}

		SIZE_T nBytes;

		if (!WriteProcessMemory(
			wr->procInfo.hProcess,
			pStr,
			&dll[0],
			dll.length() + 1,
			&nBytes
		))
		{
			winrepl_print_error("Unable to write DLL path!");
			break;
		}

		DWORD dwThreadId;

		HANDLE hThread = CreateRemoteThread(
			wr->procInfo.hProcess,
			NULL,
			0,
			(LPTHREAD_START_ROUTINE)LoadLibraryA,
			pStr,
			0,
			&dwThreadId);

		if (hThread == INVALID_HANDLE_VALUE)
		{
			winrepl_print_error("Failed to call LoadLibraryA().");
			break;
		}

		winrepl_print_good("LoadLibraryA() called for %s!", dll.c_str());

	} while (0);

	return TRUE;
}

BOOL winrepl_command_registers(winrepl_t *wr, std::vector<std::string> parts)
{
	winrepl_print_registers_all(wr);
	return TRUE;
}

static BOOL winrepl_command_reset(winrepl_t *wr, std::vector<std::string> parts)
{
	winrepl_print_good("Resetting the environment.");
	TerminateProcess(wr->procInfo.hProcess, 0);
	DebugActiveProcessStop(wr->procInfo.dwProcessId);
	return FALSE;
}

static BOOL winrepl_command_help()
{
	std::cout << ".help\t\t\tShow this help screen." << std::endl;
	std::cout << ".registers\t\tShow more detailed register info." << std::endl;
	std::cout << ".read addr size\t\tRead from a memory address." << std::endl;
	std::cout << ".write addr hexdata\tWrite to a memory address." << std::endl;
	std::cout << ".allocate size\t\tAllocate a memory buffer." << std::endl;
	std::cout << ".loadlibrary path\tLoad a DLL into the process." << std::endl;
	std::cout << ".kernel32 func\t\tGet address of a kernel32 export." << std::endl;
	//std::cout << ".dep [0/1]\t\tEnable or disable NX-bit." << std::endl;
	std::cout << ".shellcode hexdata\tExecute raw shellcode." << std::endl;
	std::cout << ".peb\t\t\tLoads PEB into accumulator." << std::endl;
	std::cout << ".reset\t\t\tStart a new environment." << std::endl;
	std::cout << ".quit\t\t\tExit the program." << std::endl;

	return TRUE;
}

BOOL winrepl_run_command(winrepl_t *wr, std::string command)
{
	std::vector<std::string> parts = split(command, " ");
	std::string mainCmd = parts[0];
	parts.erase(parts.begin());

	if (mainCmd == ".registers")
		return winrepl_command_registers(wr, parts);
	else if (mainCmd == ".read")
		return winrepl_command_read(wr, parts);
	else if (mainCmd == ".write")
		return winrepl_command_write(wr, parts);
	else if (mainCmd == ".allocate")
		return winrepl_command_allocate(wr, parts);
	else if (mainCmd == ".loadlibrary")
		return winrepl_command_loadlibrary(wr, parts);
	else if (mainCmd == ".kernel32")
		return winrepl_command_kernel32(wr, parts);
	else if (mainCmd == ".reset")
		return winrepl_command_reset(wr, parts);
	else if (mainCmd == ".shellcode")
		return winrepl_command_shellcode(wr, parts);
	else if (mainCmd == ".peb")
		return winrepl_command_peb(wr, parts);
	else if (mainCmd == ".quit" || mainCmd == ".exit")
		ExitProcess(0);
	else
	{
		if (mainCmd != ".help")
			winrepl_print_error("Command not found!");
		return winrepl_command_help();
	}


	return TRUE;
}