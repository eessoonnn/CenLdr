#include "AntiVirtual.h"


BOOL AntiSandBox()
{
	INT			cpuInfo[4]	 = { 0 };
	ULONG_PTR	ulTsc1		 = 0;
	ULONG_PTR	ulTsc2		 = 0;
	ULONG_PTR	ulAvg		 = 0;
	
	for (INT i = 0; i < 10; i++)
	{
		ulTsc1 = __rdtsc();
		__cpuid(cpuInfo, 0);
		ulTsc2 = __rdtsc();
		ulAvg += (ulTsc2 - ulTsc1);
	}

	ulAvg = ulAvg / 10;
	return (ulAvg < 1000 && ulAvg > 0) ? TRUE : FALSE;
}


BOOL AntiDebugger()
{
	PKUSER_SHARED_DATA ksd = (PKUSER_SHARED_DATA)KSHARE_DATA_ADDRESS;

	
	if (!ksd->DbgSecureBootEnabled)		goto _IsInDebug;


	if (ksd->ActiveProcessorCount <= 4)	goto _IsInDebug;


	if (ksd->KdDebuggerEnabled)			goto _IsInDebug;

	return TRUE;

_IsInDebug:
	return FALSE;
}