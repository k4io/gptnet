#pragma once
#include <Windows.h>
#include <tchar.h>

BOOL NtQueryInformationProcess_ProcessDebugPort()
{
	typedef NTSTATUS(WINAPI * pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);

	pNtQueryInformationProcess NtQueryInfoProcess = NULL;

	const int ProcessDbgPort = 7;

	NTSTATUS Status;

	DWORD dProcessInformationLength = sizeof(ULONG);
	DWORD32 IsRemotePresent = 0;

	HMODULE hNtdll = LoadLibrary("ntdll.dll");
	if (hNtdll == NULL)
	{
	}

	NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

	if (NtQueryInfoProcess == NULL)
		return 0;

	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDbgPort, &IsRemotePresent, dProcessInformationLength, NULL);
	if (Status == 0x00000000 && IsRemotePresent != 0)
		return TRUE;
	else
		return FALSE;
}

