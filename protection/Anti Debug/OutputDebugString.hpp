#pragma once
#include <Windows.h>
#include <tchar.h>
#include "../VersionHelpers.hpp"

BOOL OutputDebugStringAPI()
{
	BOOL IsDbgPresent = FALSE;
	DWORD Val = 0x29A;

	if (IsWindowsXPOr2k())
	{
		SetLastError(Val);
		OutputDebugString("45yv3645yu356u43d2411111111");

		if (GetLastError() == Val)
			IsDbgPresent = TRUE;
	}

	return IsDbgPresent;
}
