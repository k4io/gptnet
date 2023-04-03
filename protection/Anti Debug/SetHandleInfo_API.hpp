#pragma once
#include <Windows.h>
#include <tchar.h>

BOOL SetHandleInformatiom_ProtectedHandle()
{
	HANDLE hMutex;

	hMutex = CreateMutex(NULL, FALSE, "8o4527ft68947g2t8o7s45087o24");

	SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);

	__try {
		CloseHandle(hMutex);
	}

	__except (HANDLE_FLAG_PROTECT_FROM_CLOSE) {
		return TRUE;
	}

	return FALSE;
}