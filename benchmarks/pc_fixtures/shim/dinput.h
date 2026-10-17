/* build shim: the DirectX SDK is not part of the MSVC 4.2 tree. The types, constants and call macros win32 in_win.c
   (WinQuake) names for its optional DirectInput mouse path; the calls go through a pointer obtained with
   GetProcAddress at run time, so the macros here only have to type-check. */
#ifndef SHIM_DINPUT_H
#define SHIM_DINPUT_H
#include <windows.h>
#define DIRECTINPUT_VERSION 0x0300
typedef struct { int unused; } *LPDIRECTINPUT;
typedef struct { int unused; } *LPDIRECTINPUTDEVICE;
typedef struct { DWORD dwSize, dwHeaderSize, dwObj, dwHow; } DIPROPHEADER;
typedef struct { DIPROPHEADER diph; DWORD dwData; } DIPROPDWORD;
typedef struct { DWORD dwOfs, dwData, dwTimeStamp, dwSequence; } DIDEVICEOBJECTDATA;
typedef struct { const GUID *pguid; DWORD dwOfs, dwType, dwFlags; } DIOBJECTDATAFORMAT;
typedef struct { DWORD dwSize, dwObjSize, dwFlags, dwDataSize, dwNumObjs; DIOBJECTDATAFORMAT *rgodf; } DIDATAFORMAT;
static const GUID GUID_SysMouse = {0x6F1D2B60,0xD5A0,0x11CF,{0xBF,0xC7,0x44,0x45,0x53,0x54,0,0}};
static const GUID GUID_XAxis = {0xA36D02E0,0xC9F3,0x11CF,{0xBF,0xC7,0x44,0x45,0x53,0x54,0,0}};
static const GUID GUID_YAxis = {0xA36D02E1,0xC9F3,0x11CF,{0xBF,0xC7,0x44,0x45,0x53,0x54,0,0}};
static const GUID GUID_ZAxis = {0xA36D02E2,0xC9F3,0x11CF,{0xBF,0xC7,0x44,0x45,0x53,0x54,0,0}};
#define DIPH_DEVICE 0
#define DIPROP_BUFFERSIZE (&GUID_XAxis)
#define DISCL_EXCLUSIVE 1
#define DISCL_FOREGROUND 4
#define DIDF_RELAXIS 2
#define DIDFT_AXIS 3
#define DIDFT_ANYINSTANCE 0x00FFFF00
#define DIDFT_BUTTON 0x0C
#define DIDFT_OPTIONAL 0x80000000
#define DIERR_INPUTLOST 0x8007001E
#define DIERR_NOTACQUIRED 0x8007000C
#define DIMOFS_X 0
#define DIMOFS_Y 4
#define DIMOFS_Z 8
#define DIMOFS_BUTTON0 12
#define DIMOFS_BUTTON1 13
#define DIMOFS_BUTTON2 14
#define DIMOFS_BUTTON3 15
#define IDirectInputDevice_Acquire(p) ((void)(p), 0)
#define IDirectInputDevice_Unacquire(p) ((void)(p), 0)
#define IDirectInputDevice_Release(p) ((void)(p), 0)
#define IDirectInput_Release(p) ((void)(p), 0)
#define IDirectInput_CreateDevice(p,g,d,u) ((void)(p), (void)(g), (void)(d), (void)(u), 0)
#define IDirectInputDevice_SetDataFormat(p,f) ((void)(p), (void)(f), 0)
#define IDirectInputDevice_SetCooperativeLevel(p,w,f) ((void)(p), (void)(w), (void)(f), 0)
#define IDirectInputDevice_SetProperty(p,g,h) ((void)(p), (void)(g), (void)(h), 0)
#define IDirectInputDevice_GetDeviceData(p,s,d,n,f) ((void)(p), (void)(s), (void)(d), (void)(n), (void)(f), 0)
#endif
