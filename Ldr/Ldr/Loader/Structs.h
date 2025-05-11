#pragma once
#include "SelfAchive.h"
#include <windows.h>

#define PROCESSOR_FEATURE_MAX 64


typedef  VOID(*evaSleep)(DWORD);
typedef  BOOL(*evaCloseHandle)(HANDLE);
typedef  BOOL(*evaReadFile)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef  BOOL(*evaUnmapViewOfFile)(LPCVOID);
typedef  DWORD(*evaGetFileSize)(HANDLE, LPDWORD);
typedef  LPVOID(*evaMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef  HANDLE(*evaCreateFileW)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef  HANDLE(*evaGetModuleHandleW)(LPCWSTR);
typedef  HANDLE(*evaCreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR); 
typedef  NTSTATUS(*evaLdrLoadDll)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef  NTSTATUS(*evaNtProtectVirtualMemory)(HANDLE, PVOID*, PULONG, ULONG, PULONG);
typedef  NTSTATUS(*evaNtCreateThreadEx)(PHANDLE,ACCESS_MASK ,POBJECT_ATTRIBUTES,HANDLE,PUSER_THREAD_START_ROUTINE,PVOID,ULONG, SIZE_T,SIZE_T,SIZE_T,PPS_ATTRIBUTE_LIST );
typedef  NTSTATUS(*evaNtGetContextThread)( HANDLE,PCONTEXT);
typedef  NTSTATUS(*evaNtSetContextThread)(HANDLE,PCONTEXT);
typedef  NTSTATUS(*evaNtResumeThread)(HANDLE,PULONG);
typedef  NTSTATUS(*evaNtWaitForSingleObject)(HANDLE ,BOOLEAN ,PLARGE_INTEGER );


typedef struct _Win32Api
{
	evaSleep                    pfnSleep;
    evaReadFile                 pfnReadFile;
    evaLdrLoadDll               pfnLdrLoadDll;
	evaCloseHandle              pfnCloseHandle;
	evaCreateFileW              pfnCreateFileW;
	evaGetFileSize              pfnGetFileSize;
	evaMapViewOfFile            pfnMapViewOfFile;
	evaNtResumeThread           pfnNtResumeThread;
    evaUnmapViewOfFile          pfnUnmapViewOfFile;
    evaNtCreateThreadEx         pfnNtCreateThreadEx;
    evaGetModuleHandleW         pfnGetModuleHandleW;
	evaNtGetContextThread       pfnNtGetContextThread;
	evaNtSetContextThread       pfnNtSetContextThread;
    evaCreateFileMappingW       pfnCreateFileMappingW;
    evaNtWaitForSingleObject    pfnNtWaitForSingleObject;
    evaNtProtectVirtualMemory   pfnNtProtectVirtualMemory;
    ULONG_PTR                   ulTpReleaseCleanupGroupMembers;
}Win32Api,*PWin32Api;

typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME,
* PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE,
* PNT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
    StandardDesign,
    NEC98x86,
    EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA {
    ULONG                         TickCountLowDeprecated;
    ULONG                         TickCountMultiplier;
    KSYSTEM_TIME                  InterruptTime;
    KSYSTEM_TIME                  SystemTime;
    KSYSTEM_TIME                  TimeZoneBias;
    USHORT                        ImageNumberLow;
    USHORT                        ImageNumberHigh;
    WCHAR                         NtSystemRoot[260];
    ULONG                         MaxStackTraceDepth;
    ULONG                         CryptoExponent;
    ULONG                         TimeZoneId;
    ULONG                         LargePageMinimum;
    ULONG                         AitSamplingValue;
    ULONG                         AppCompatFlag;
    ULONGLONG                     RNGSeedVersion;
    ULONG                         GlobalValidationRunlevel;
    LONG                          TimeZoneBiasStamp;
    ULONG                         NtBuildNumber;
    NT_PRODUCT_TYPE               NtProductType;
    BOOLEAN                       ProductTypeIsValid;
    BOOLEAN                       Reserved0[1];
    USHORT                        NativeProcessorArchitecture;
    ULONG                         NtMajorVersion;
    ULONG                         NtMinorVersion;
    BOOLEAN                       ProcessorFeatures[PROCESSOR_FEATURE_MAX];
    ULONG                         Reserved1;
    ULONG                         Reserved3;
    ULONG                         TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG                         BootId;
    LARGE_INTEGER                 SystemExpirationDate;
    ULONG                         SuiteMask;
    BOOLEAN                       KdDebuggerEnabled;
    union {
        UCHAR MitigationPolicies;
        struct {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };
    USHORT                        CyclesPerYield;
    ULONG                         ActiveConsoleId;
    ULONG                         DismountCount;
    ULONG                         ComPlusPackage;
    ULONG                         LastSystemRITEventTickCount;
    ULONG                         NumberOfPhysicalPages;
    BOOLEAN                       SafeBootMode;
    union {
        UCHAR VirtualizationFlags;
        struct {
            UCHAR ArchStartedInEl2 : 1;
            UCHAR QcSlIsSupported : 1;
        };
    };
    UCHAR                         Reserved12[2];
    union {
        ULONG SharedDataFlags;
        struct {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgConsoleBrokerEnabled : 1;
            ULONG DbgSecureBootEnabled : 1;
            ULONG DbgMultiSessionSku : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG SpareBits : 21;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
    ULONG                         DataFlagsPad[1];
    ULONGLONG                     TestRetInstruction;
    LONGLONG                      QpcFrequency;
    ULONG                         SystemCall;
    ULONG                         Reserved2;
    ULONGLONG                     FullNumberOfPhysicalPages;
    ULONGLONG                     SystemCallPad[1];
    union {
        KSYSTEM_TIME TickCount;
        ULONG64      TickCountQuad;
        struct {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME3;
    ULONG                         Cookie;
    ULONG                         CookiePad[1];
    LONGLONG                      ConsoleSessionForegroundProcessId;
    ULONGLONG                     TimeUpdateLock;
    ULONGLONG                     BaselineSystemTimeQpc;
    ULONGLONG                     BaselineInterruptTimeQpc;
    ULONGLONG                     QpcSystemTimeIncrement;
    ULONGLONG                     QpcInterruptTimeIncrement;
    UCHAR                         QpcSystemTimeIncrementShift;
    UCHAR                         QpcInterruptTimeIncrementShift;
    USHORT                        UnparkedProcessorCount;
    ULONG                         EnclaveFeatureMask[4];
    ULONG                         TelemetryCoverageRound;
    USHORT                        UserModeGlobalLogger[16];
    ULONG                         ImageFileExecutionOptions;
    ULONG                         LangGenerationCount;
    ULONGLONG                     Reserved4;
    ULONGLONG                     InterruptTimeBias;
    ULONGLONG                     QpcBias;
    ULONG                         ActiveProcessorCount;
    UCHAR                         ActiveGroupCount;
    UCHAR                         Reserved9;
    union {
        USHORT QpcData;
        struct {
            UCHAR QpcBypassEnabled;
            UCHAR QpcReserved;
        };
    };
    LARGE_INTEGER                 TimeZoneBiasEffectiveStart;
    LARGE_INTEGER                 TimeZoneBiasEffectiveEnd;
    XSTATE_CONFIGURATION          XState;
    KSYSTEM_TIME                  FeatureConfigurationChangeStamp;
    ULONG                         Spare;
    ULONG64                       UserPointerAuthMask;
    XSTATE_CONFIGURATION          XStateArm64;
    ULONG                         Reserved10[210];
} KUSER_SHARED_DATA,
* PKUSER_SHARED_DATA;