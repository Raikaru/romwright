/* build shim: win32/snd_win.c (DirectSound) is not built; the one symbol vid_dll.c needs from it */
typedef int qboolean;
void S_Activate (qboolean active) { (void)active; }
