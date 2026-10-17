#include <windows.h>
int __stdcall mainstart(void) { DWORD n; HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE); WriteFile(h, "hi\n", 3, &n, 0); ExitProcess(0); return 0; }
