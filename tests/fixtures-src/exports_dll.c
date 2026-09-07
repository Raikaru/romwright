/* PE32 DLL fixture with three exported functions and one static helper.
   The exported entries are reachable only through the export directory:
   nothing inside the image calls them.
   Compiled with:
   i686-w64-mingw32-gcc -O2 -g -shared -o exports32.dll exports_dll.c
*/
static int scale(int value) { return value * 3; }

__declspec(dllexport) int exported_add(int a, int b) { return a + b; }
__declspec(dllexport) int exported_scaled(int value) { return scale(value) + 1; }
__declspec(dllexport) int exported_chain(int value) { return exported_add(value, scale(value)); }
