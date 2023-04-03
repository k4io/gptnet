#pragma once
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

DWORD GetProcIDFromName(LPCTSTR szProcessName)
{
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = NULL;
	SecureZeroMemory(&pe32, sizeof(PROCESSENTRY32));

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32) == FALSE)
	{
		CloseHandle(hSnapshot);
		return 0;
	}

	if (StrCmpI(pe32.szExeFile, szProcessName) == 0)
	{
		CloseHandle(hSnapshot);
		return pe32.th32ProcessID;
	}

	while (Process32Next(hSnapshot, &pe32))
	{
		if (StrCmpI(pe32.szExeFile, szProcessName) == 0)
		{
			CloseHandle(hSnapshot);
			return pe32.th32ProcessID;
		}
	}

	CloseHandle(hSnapshot);
	return 0;
}

VOID ErasePEHeaderFromMemory( )
{
	DWORD OldProtect = 0;

	char* pBaseAddr = ( char* ) GetModuleHandle( NULL );

	VirtualProtect( pBaseAddr, 4096, PAGE_READWRITE, &OldProtect );

	SecureZeroMemory( pBaseAddr, 4096 );
}