#pragma once
#include <Windows.h>
#include <tchar.h>
#include <winternl.h>
#include <Shlwapi.h>

BOOL NtQueryObject_ObjectAllTypesInformation();
BOOL NtQueryObject_ObjectTypeInformation();


#define DEBUG_READ_EVENT 0x0001
#define DEBUG_PROCESS_ASSIGN 0x0002
#define DEBUG_SET_INFORMATION 0x0004
#define DEBUG_QUERY_INFORMATION 0x0008
#define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
    DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | \
    DEBUG_QUERY_INFORMATION)

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfHandles;
	ULONG TotalNumberOfObjects;
}OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION {
	ULONG NumberOfObjects;
	OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
}OBJECT_ALL_INFORMATION, * POBJECT_ALL_INFORMATION;

BOOL NtQueryObject_ObjectTypeInformation()
{
	typedef NTSTATUS(WINAPI * pNtQueryObject)(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
	typedef NTSTATUS(WINAPI * pNtCreateDebugObject)(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG);

	pNtQueryObject NtQueryObject = NULL;
	pNtCreateDebugObject NtCreateDebugObject = NULL;

	HANDLE DebugObjectHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, 0, 0, 0, 0);
	BYTE memory[0x1000] = { 0 };
	POBJECT_TYPE_INFORMATION ObjectInformation = (POBJECT_TYPE_INFORMATION)memory;
	NTSTATUS Status;


	HMODULE hNtdll = LoadLibrary("ntdll.dll");
	if (hNtdll == NULL)
	{
	}

	NtCreateDebugObject = (pNtCreateDebugObject)GetProcAddress(hNtdll, "NtCreateDebugObject");
	if (NtCreateDebugObject == NULL)
	{
	}

	NtCreateDebugObject(&DebugObjectHandle, DEBUG_ALL_ACCESS, &ObjectAttributes, FALSE);
	if (NtCreateDebugObject) {

		HMODULE hNtdll = LoadLibrary("ntdll.dll");
		if (hNtdll == NULL)
		{
		}

		NtQueryObject = (pNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
		if (NtCreateDebugObject == NULL)
		{
		}

		Status = NtQueryObject(DebugObjectHandle, ObjectTypeInformation, ObjectInformation, sizeof(memory), 0);

		CloseHandle(DebugObjectHandle);


		if (Status >= 0)
		{
			if (ObjectInformation->TotalNumberOfObjects == 0)
				return TRUE;
			else
				return FALSE;
		}
		else
		{
			return FALSE;
		}
	}
	else
		return FALSE;

}