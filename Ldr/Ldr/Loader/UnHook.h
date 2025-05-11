#pragma once
#include <Windows.h>
#include "Structs.h"
#include <psapi.h>

#define NTDLL				L"C:\\Windows\\System32\\ntdll.dll"
#define KERNEL32			L"C:\\Windows\\System32\\kernel32.dll"
#define KERNELBASE			L"C:\\Windows\\System32\\kernelbase.dll"
#define ADVAPI32			L"C:\\Windows\\System32\\advapi32.dll"
#define WININET				L"C:\\Windows\\System32\\wininet.dll"
#define WS2_32				L"C:\\Windows\\System32\\ws2_32.dll"
#define TEXTSECTIONHASH		0x7B5B1175
BOOL UnHook(PWin32Api win32Api);