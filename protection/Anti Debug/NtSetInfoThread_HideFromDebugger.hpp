#pragma once
#include <Windows.h>
#include <tchar.h>

BOOL NtSetInformationThread_ThreadHideFromDebugger()
{
	typedef NTSTATUS(WINAPI * pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);

	const int ThreadHideFromDebugger = 0x11;

	pNtSetInformationThread NtSetInformationThread = NULL;

	NTSTATUS Status;
	BOOL IsBeingDebug = FALSE;

	HMODULE hNtDll = LoadLibrary("ntdll.dll");
	if (hNtDll == NULL)
	{
	}

	NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");

	if (NtSetInformationThread == NULL)
	{
	}

	Status = NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);

	if (Status)
		IsBeingDebug = TRUE;

	return IsBeingDebug;
}