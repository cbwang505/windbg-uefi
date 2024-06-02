
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

//
// Shell Library
//
#include <Library/ShellLib.h>


#include "stdint.h"

#include "utils.h"





static void getByteString(uint32_t startaddr, uint8_t* bytesbuf,
	int bytesread)
{



	if (bytesread < 1) {
		return;
	}

	if (bytesread > 16) {
		return;
	}


	//wchar_t* bytestr_tmp = (wchar_t*)L"";
	wchar_t* bytestr_hex = (wchar_t*)L"";
	uint8_t c[0x10];
	for (int i = 0; i < bytesread; i++) {
		c[i] = *(bytesbuf + i);
		//bytestr_tmp = CatSPrint(bytestr_tmp, L"%02x ", c);
	}
	if (bytesread < 16) {
		for (int i = bytesread; i < 16; i++) {
			//bytestr_tmp = CatSPrint(bytestr_tmp, L"%02x ", 0);
			c[i] = 0;
		}
	}
	wchar_t* charstr_tmp = L"";
	for (int i = 0; i < bytesread; i++) {
		uint8_t cd = *(bytesbuf + i);
		if ((cd < 127) && (cd > 31) && (cd != 92) && (cd != 34) &&
			(cd != 37)) // exclude '\'=92 and "=34 for JSON comp.
		{
			charstr_tmp = CatSPrint(charstr_tmp, L"%c", cd);
		}

		else {
			charstr_tmp = CatSPrint(charstr_tmp, L".");
		}
	}
	int idx = 0;
	bytestr_hex = CatSPrint(bytestr_hex, L"%02x %02x %02x %02x ", c[idx], c[idx + 1], c[idx + 2], c[idx + 3]);
	idx += 4;
	bytestr_hex = CatSPrint(bytestr_hex, L"%02x %02x %02x %02x ", c[idx], c[idx + 1], c[idx + 2], c[idx + 3]);
	idx += 4;
	bytestr_hex = CatSPrint(bytestr_hex, L"%02x %02x %02x %02x ", c[idx], c[idx + 1], c[idx + 2], c[idx + 3]);
	idx += 4;
	bytestr_hex = CatSPrint(bytestr_hex, L"%02x %02x %02x %02x ", c[idx], c[idx + 1], c[idx + 2], c[idx + 3]);

	Print(L"%04x %s %s\n", startaddr, bytestr_hex, charstr_tmp);

	return;
}

static void hexdump(uint8_t* bytesbufRef, int size_len)
{
	Print(L"hexdump! buf ptr:=> %016llx,len  %08x!\n", bytesbufRef, size_len);
	int idx = size_len / 16;
	for (int i = 0; i <= idx; i++) {
		int  len = (i * 16) + 16 > size_len ? size_len % 16 : 16;
		getByteString((i * 16), bytesbufRef + (i * 16), len);
	}
	return;
}

void dumpbuf(void* buf, int len)
{
	hexdump((uint8_t*)buf, len);
	return;
}

void dumphex(void* buf, int len)
{

	Print(L"{");
	for (int i = 0; i < len; i++) {
		uint8_t c = *(((uint8_t*)buf) + i);
		if (i == len - 1) {
			Print(L"0x%02x};\r\n;", c);
		}
		else {
			Print(L"0x%02x,", c);
		}
	}
}



void
hvresetmemory(
	void* dest,
	UINT32  count
)
{
	gBS->SetMem(dest, count, 0);
	return;

}
void
hvresetmemoryimp(
	void* dest,
	UINT32  count
)
{
	UINT64* Pointer64 = (UINT64*)dest;
	if (count >= 8)
	{
		while (count >= 8) {
			*(Pointer64++) = 0;
			count -= 8;
		}
	}
	if (count > 0) {
		UINT8* Pointer = (UINT8*)Pointer64;
		while (count-- != 0) {
			*(Pointer++) = 0;
		}
	}
	return;
}

void*
hvcopymemory(
	void* dest,
	void* src,
	UINT32  count
) {
	gBS->CopyMem(dest, src, count);
	return dest;
}


void*
hvcopymemoryimp(
	void* dest,
	void* src,
	UINT32  count
)
{

	UINT64* Pointer64;
	UINT64* Pointer264;
	UINT8* Pointer;
	UINT8* Pointer2;
	Pointer64 = (UINT64*)dest;
	Pointer264 = (UINT64*)src;
	if (count >= 8)
	{
		while (count >= 8) {
			*(Pointer64++) = *(Pointer264++);
			count -= 8;
		}
	}
	if (count > 0) {
		Pointer = (UINT8*)Pointer64;
		Pointer2 = (UINT8*)Pointer264;
		while (count-- != 0) {
			*(Pointer++) = *(Pointer2++);
		}
	}

	return dest;
}





void
hvwcscpy(
	WCHAR* dest,
	WCHAR* src
)
{
	WCHAR* Pointer = (WCHAR*)src;
	WCHAR* Pointer1 = (WCHAR*)dest;
	while (*Pointer != L'\0') {
		*Pointer1 = *Pointer;
		Pointer++;
		Pointer1++;
	}
	*Pointer1 = L'\0';
	return;
}


int w2s(wchar_t* src, char* dest)
{
	int idx = 0;

	wchar_t* Pointer = src;
	char* Pointer1 = dest;
	if (*Pointer == L'\0')
	{
		return idx;
	}

	while (TRUE)
	{
		if (*Pointer == L'\0')
		{
			*Pointer1 = '\0';

			return idx;
		}
		else
		{
			*Pointer1 = (char)(*Pointer);
			Pointer++;
			Pointer1++;
			idx++;
		}

	}

	return idx;

}