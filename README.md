# WinREPL
WinREPL is a "read-eval-print loop" for x86 and x64 assembly on Windows systems. It is similar to yrp604/rappel (Linux) and Tyilo/asm_repl (Mac).

![WinREPL](/screenshot.png?raw=true "WinREPL")

### Methodology
WinREPL is a debugger (parent process) that hollows out a copy of itself (child process).

1. Parent process retrieves input from the user
2. Machine code is generated with the Keystone library
3. Resulting bytes are written to a child process thread context
4. Child process thread is resumed
5. Parent process polls for debug events

### Commands
Besides being a raw assembler, there are a few extra commands.

```
.help                   Show this help screen.
.registers              Show more detailed register info.
.read addr size         Read from a memory address.
.write addr hexdata     Write to a memory address.
.allocate size          Allocate a memory buffer.
.loadlibrary path       Load a DLL into the process.
.kernel32 func          Get address of a kernel32 export.
.shellcode hexdata      Execute raw shellcode.
.peb                    Loads PEB into accumulator.
.reset                  Start a new environment.
.quit                   Exit the program.
```

### Building
As I don't want to go to prison, the provided binaries (winrepl_x86.exe and winrepl_x64.exe) are not backdoored. That said, this program works via sorcery that is probably suspicious to antivirus.

You may wish to build from source for various reasons. At this time, all development is done in VS2015. If you use a different version, you will need to re-compile the Keystone .lib files with the same Microsoft compiler (cl.exe). Refer to http://www.keystone-engine.org/

## Todo
As always happens, code is rushed and awful.

1. Clean up the hodge-podge of C and C++
2. Look into label support
3. Better error handling for debug events
4. Better command mappings

### License
The project statically links Keystone and must therefore be GPLv2.