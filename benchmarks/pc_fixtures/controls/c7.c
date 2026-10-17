typedef unsigned long DWORD; typedef void *HANDLE;
extern HANDLE __stdcall GetStdHandle(DWORD);
extern int __stdcall WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
extern void __stdcall ExitProcess(unsigned);
int __stdcall mainstart(void) { DWORD n; HANDLE h = GetStdHandle((DWORD)-11); WriteFile(h, "hi\n", 3, &n, 0); ExitProcess(0); return 0; }
