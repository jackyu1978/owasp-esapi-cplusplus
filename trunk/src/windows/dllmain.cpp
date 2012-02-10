// dllmain.cpp : Defines the entry point for the DLL application.

#include <windows.h>

#define  SET_CRT_DEBUG_FIELD(a) \
            _CrtSetDbgFlag((a) | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG))
#define  CLEAR_CRT_DEBUG_FIELD(a) \
            _CrtSetDbgFlag(~(a) & _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG))

#if 1
# define _CRTDBG_MAP_ALLOC
# include <stdlib.h>
# include <crtdbg.h>
#endif

BOOL APIENTRY DllMain( HMODULE /**hModule*/, DWORD  dwReason, LPVOID /**lpReserved*/ )
{
  SET_CRT_DEBUG_FIELD( _CRTDBG_DELAY_FREE_MEM_DF );

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
