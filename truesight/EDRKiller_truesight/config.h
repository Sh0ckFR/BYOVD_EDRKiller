/*
		Store all variables and settings used across the project
*/

#pragma once

// Define path for the driver file
#define g_VULNDRIVERPATH		L"\\System32\\Drivers\\"		// Default runtime-loaded kernel drivers

// Define variables for the vulnerable driver
#define g_VULNDRIVERNAME		L"adlice"
#define g_VULNDRIVERFILENAME	L"truesight.sys"
#define g_VULNDRIVERSYMLINK		L"\\\\.\\TrueSight"

// Define IOCTL code
#define IOCTL_CODE				0x22e044

// Define the sleep time
#define g_SLEEPTIME				1000