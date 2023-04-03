#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include "../VersionHelpers.hpp"
#include "../EreasePEHeader.hpp"


DWORD GetCsrssProcessId()
{
	if (IsWindowsXPOrGreater())
	{
		typedef DWORD(NTAPI * pCsrGetId)(VOID);

		pCsrGetId CsrGetProcessId = (pCsrGetId)GetProcAddress(GetModuleHandle("ntdll.dll"), "CsrGetProcessId");

		if (CsrGetProcessId)
			return CsrGetProcessId();
		else
			return 0;
	}
	else
		return GetProcIDFromName( "csrss.exe" );
}


BOOL CanOpenCsrss()
{
	HANDLE hCsrss = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCsrssProcessId());
	if (hCsrss != NULL)
	{
		CloseHandle(hCsrss);
		return TRUE;
	}
	else
		return FALSE;
}