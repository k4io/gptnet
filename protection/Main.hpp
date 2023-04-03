#pragma once

#include "Anti Debug/CheckRemoteDebuggerPresent.hpp"
#include "Anti Debug/NtGlobalFlag.hpp"
#include "Anti Debug/NtQueryInfo_ProcessDebugPort.hpp"
#include "Anti Debug/NtQueryInfo_ProcessDebugFlags.h"
#include "Anti Debug/NtQueryInfo_ProcessDebugObject.hpp"
#include "Anti Debug/NtSetInfoThread_HideFromDebugger.hpp"
#include "Anti Debug/CloseHandle_InvalidHandle.hpp"
#include "Anti Debug/UnhandledExceptionFilter.hpp"
#include "Anti Debug/OutputDebugString.hpp"
#include "Anti Debug/HardwareBreakpoints.hpp"
#include "Anti Debug/SoftwareBreakpoints.hpp"
#include "Anti Debug/Interrupt_3.hpp"
#include "Anti Debug/MemoryBreakpoints_PageGuard.hpp"
#include "Anti Debug/ParentProcess.hpp"
#include "Anti Debug/SeDebugPrivilege.hpp"
#include "Anti Debug/NtQueryObj_ObjTypeInfo.hpp"
#include "Anti Debug/SetHandleInfo_API.hpp"

#include "EreasePEHeader.hpp"
#include "LazyImporter.hpp"
#include <string>
#include <Psapi.h>

//#include "../Globals.hpp"

#pragma comment(lib, "Psapi.lib")

bool IsDebugging( )
{
	if ( IsDebuggerPresent( ) || CheckRemoteDebuggerPresentAPI( ) || NtGlobalFlag( )
		|| NtQueryInformationProcess_ProcessDebugPort( ) || NtQueryInformationProcess_ProcessDebugFlags( ) || NtQueryInformationProcess_ProcessDebugObject( )
		|| NtSetInformationThread_ThreadHideFromDebugger( ) || CloseHandle_InvalideHandle( ) || UnhandledExcepFilterTest( ) || OutputDebugStringAPI( )
		|| HardwareBreakpoints( ) || SoftwareBreakpoints( ) || Interrupt_3( ) || MemoryBreakpoints_PageGuard( ) || CanOpenCsrss( )
		|| NtQueryObject_ObjectTypeInformation( ) || SetHandleInformatiom_ProtectedHandle( ) )
		return true;

	return false;
}

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

bool IsAnalysing( )
{
	auto m_fnIsRemoteSession = [ ] ( ) -> bool
	{
		const int m_iSessionMetrics = GetSystemMetrics( SM_REMOTESESSION );
		return m_iSessionMetrics != 0;
	};

	auto m_fnCheckRemoteDrivers = [ ] ( ) -> bool
	{
		LPVOID m_pDrivers[ 1024 ];
		DWORD m_dwNeeded;
		int m_iDrivers;
		if (EnumDeviceDrivers( m_pDrivers, sizeof( m_pDrivers ), &m_dwNeeded ) && m_dwNeeded < sizeof( m_pDrivers ) )
		{
			LPSTR m_szDriver;
			m_iDrivers = m_dwNeeded / sizeof( m_pDrivers[ 0 ] );

			for ( int i = 0; i < m_iDrivers; i++ )
			{
				if ( K32GetDeviceDriverBaseNameA( m_pDrivers[ i ], m_szDriver, sizeof( m_szDriver ) / sizeof( m_szDriver[ 0 ] ) ) )
				{
					if ( strcmp( m_szDriver, "npf.sys") == 0 )
						return true;
					if ( strcmp( m_szDriver, "rweverything.sys") == 0 )
						return true;
					if ( strcmp( m_szDriver, "asrdrv104.sys") == 0 )
						return true;
				}
			}
		}
		return false;
	};

	std::string m_szProcesses[ ] = 
	{
		"ollydbg.exe"  ,			// OllyDebug debugger
		"ProcessHacker.exe"  ,		// Process Hacker
		"tcpview.exe"  ,			// Part of Sysinternals Suite
		"autoruns.exe"  ,			// Part of Sysinternals Suite
		"autorunsc.exe"  ,			// Part of Sysinternals Suite
		"filemon.exe"  ,			// Part of Sysinternals Suite
		"procmon.exe"  ,			// Part of Sysinternals Suite
		"ksdumper.exe"  ,			// KSDUMPER
		"ksdumperclient.exe"  ,			// KSDUMPER
		"regmon.exe"  ,			// Part of Sysinternals Suite
		"procexp.exe"  ,			// Part of Sysinternals Suite
		"idaq.exe"  ,				// IDA Pro Interactive Disassembler
		"ida.exe"  ,				// IDA Pro Interactive Dissasembler
		"idaq64.exe"  ,			// IDA Pro Interactive Disassembler
		"ImmunityDebugger.exe"  ,	// ImmunityDebugger
		"Wireshark.exe"  ,			// Wireshark packet sniffer
		"dumpcap.exe"  ,			// Network traffic dump tool
		"HookExplorer.exe"  ,		// Find various types of runtime hooks
		"ImportREC.exe"  ,			// Import Reconstructor
		"PETools.exe"  ,			// PE Tool
		"LordPE.exe"  ,			// LordPE
		"dumpcap.exe"  ,			// Network traffic dump tool
		"SysInspector.exe"  ,		// ESET SysInspector
		"proc_analyzer.exe"  ,		// Part of SysAnalyzer iDefense
		"sysAnalyzer.exe"  ,		// Part of SysAnalyzer iDefense
		"sniff_hit.exe"  ,			// Part of SysAnalyzer iDefense
		"windbg.exe"  ,			// Microsoft WinDbg
		"joeboxcontrol.exe"  ,		// Part of Joe Sandbox
		"joeboxserver.exe"  ,		// Part of Joe Sandbox
		"x32dbg.exe"  ,			// x32dbg
		"x64dbg.exe"  ,			// x64dbg
		"x96dbg.exe"  				// x64dbg part
	};

	WORD m_iLength = sizeof( m_szProcesses ) / sizeof( m_szProcesses[ 0 ] );
	for ( int i = 0; i < m_iLength; i++ )
	{
		if ( GetProcIDFromName( (LPCTSTR)m_szProcesses[ i ].c_str( ) ) )
			return true;
	}

	return ( m_fnIsRemoteSession( ) || m_fnCheckRemoteDrivers( ) );
}

void HandleUserActivity( )
{
	if ( IsDebugging( ) || IsAnalysing( ) )
	{
		ErasePEHeaderFromMemory( );

		HANDLE m_hProcess = LI_FN( OpenProcess )( PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, 0, GetCurrentProcessId( ) );
		TerminateProcess( m_hProcess, 0 );
	}
}