
//
// Basic UEFI Libraries
//
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>

//
// Boot and Runtime Services
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>




#include "stdint.h"

#include "utils.h"

#include <intrin.h>

UINTN __security_cookie = 0;

void __cdecl __security_init_cookie(void)
{
	UINT64  Cookie = __rdtsc();
	
	__security_cookie = (UINTN)Cookie;
}

__declspec(noreturn) void __cdecl __report_gsfailure(UINTN StackCookie)
{
	
	__fastfail(0);
	CpuDeadLoop();
	//return;
}

__declspec(noreturn) void __cdecl __report_rangecheckfailure()
{
	
	__fastfail(0);
	CpuDeadLoop();
	//return;
}

void __cdecl __security_check_cookie(UINTN cookie)
{
	if (cookie == __security_cookie) {
		return;
	}

	__report_gsfailure(cookie);
	return;
}

void __GSHandlerCheck(void)
{
	__fastfail(0);
	// dummy
	CpuDeadLoop();
	return;
}


void __C_specific_handler(void)
{
	__fastfail(0);
	// dummy
	CpuDeadLoop();
	return;
}