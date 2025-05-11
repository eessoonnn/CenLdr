#pragma once
#include <Windows.h>
#include <intrin.h>
#include "Structs.h"

#define KSHARE_DATA_ADDRESS 0x7FFE0000

BOOL AntiSandBox();
BOOL AntiDebugger();