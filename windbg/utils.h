
#ifndef __PI_UTILS_H__
#define __PI_UTILS_H__

#include "uefiintsafe.h"
typedef enum
{
	KDP_PACKET_RECEIVED = 0,
	KDP_PACKET_TIMEOUT = 1,
	KDP_PACKET_RESEND = 2,
	KDP_PACKET_RECHECK = 3,
	KDP_PACKET_CONTINUE = 4
} KDP_STATUS;
void
hvresetmemory(
	void* dest,
	UINT32  count
);
void*
hvcomparememory(
	void* dest,
	void* src,
	UINT32  count
);
void
hvwcscpy(
	WCHAR* dest,
	WCHAR* src
);
void*
hvcopymemory(
	void* dest,
	void* src,
	UINT32  count);
void stall(int multi);
//void *
//CopyMem(
//	 void* Destination,
//	const void* Source,
//	 UINT32  Length
//);
void dumpbuf(void* buf, int len);

WCHAR* GetPDBInfo(UINT8* m_pBuffer, UINT32* m_pCheckSum, UINT32* m_pSizeOfImage);
WCHAR* GetModuleName(UINT8* m_pBuffer, UINT32* m_pCheckSum, UINT32* m_pSizeOfImage);
int w2s(wchar_t* src, char* dest);
VOID
EFIAPI
DisableInterrupts(
	VOID
); 
VOID
EFIAPI
EnableInterrupts(
	VOID
);


VOID
NTAPI
KdpDprintf(
	_In_ CHAR16* FormatString,
	...);


#define HYPERVISOR_CALLBACK_VECTOR 0x27

#endif