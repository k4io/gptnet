#pragma once
#include <Windows.h>
#include <tchar.h>

BOOL NtQueryInformationProcess_ProcessDebugObject()
{
	typedef NTSTATUS(WINAPI * pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);

	const int ProcessDebugObjectHandle = 0x1e;

	pNtQueryInformationProcess NtQueryInfoProcess = NULL;

	NTSTATUS Status;
	HANDLE hDebugObject = NULL;

	DWORD dProcessInformationLength = sizeof(ULONG);
	DWORD32 IsRemotePresent = 0;

	HMODULE hNtDll = LoadLibrary("ntdll.dll");
	if (hNtDll == NULL)
	{
	}

	NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

	if (NtQueryInfoProcess == NULL)
	{
	}

	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, dProcessInformationLength, NULL);

	if (Status == 0x00000000 && hDebugObject)
		return TRUE;
	else
		return FALSE;
}