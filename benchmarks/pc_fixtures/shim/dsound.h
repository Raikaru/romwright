/* build shim: the DirectX SDK is not part of the MSVC 8.0 toolchain tree; Quake 2 names two DirectSound types in
   win32/winquake.h and uses them only in the (unbuilt here) snd_win.c */
typedef struct IDirectSound *LPDIRECTSOUND;
typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;
