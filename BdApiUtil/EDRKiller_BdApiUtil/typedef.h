/*
	 Defines all the typedef definitions used across the project
*/

#pragma once

#include <Windows.h>
#include "config.h"

// ***** TYPEDEF FOR killEDR.c ***** //
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);