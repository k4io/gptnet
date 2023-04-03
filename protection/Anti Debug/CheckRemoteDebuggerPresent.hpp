#pragma once
#include <Windows.h>

BOOL CheckRemoteDebuggerPresentAPI( VOID )
{
	BOOL m_bIsDebugging = FALSE;
	CheckRemoteDebuggerPresent( GetCurrentProcess( ), &m_bIsDebugging );
	return m_bIsDebugging;
}