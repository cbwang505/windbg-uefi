
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>

#include <Library/PeCoffExtraActionLib.h>
//
//
// Boot and Runtime Services
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>



#include "stdint.h"

//
// Shell Library
//
#include <Library/ShellLib.h>

#include "windbg.h"

extern BOOLEAN ForceConsoleOutput;

EFI_GUID gEfiWindbgProtocolGUID = { 0xd6ef2483,0xa5de,0x4fa4,{0x8b,0xc3,0x83,0x92,0x50,0xb6,0xff,0xfd} };

PEFI_WINDBGPROTOCOL pWindbgProtocol = NULL;


UINT8 mErrorMsgVersionAlert[0x100];

BOOLEAN  EnableWindbgPluginInitialized = FALSE;
UINTN
EFIAPI
PeCoffSearchImageBaseWindbg(
	IN UINTN  Address
)
{
	UINTN  Pe32Data;

	Pe32Data = 0;

	//DEBUG_CODE_BEGIN();
	EFI_IMAGE_DOS_HEADER* DosHdr;
	EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;

	//
	// Find Image Base
	//
	Pe32Data = Address & ~(SIZE_4KB - 1);
	//Print(L"ImageContext.Pe32Data Start %p\r\n", Pe32Data);
	while (Pe32Data != 0) {
		DosHdr = (EFI_IMAGE_DOS_HEADER*)Pe32Data;
		if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
			//
			// DOS image header is present, so read the PE header after the DOS image header.
			//
			Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32*)(Pe32Data + (UINTN)((DosHdr->e_lfanew) & 0x0ffff));
			//
			// Make sure PE header address does not overflow and is less than the initial address.
			//

			if (Hdr.Pe32->Signature == EFI_IMAGE_NT_SIGNATURE) {
				break;
			}
			break;
		}
		else {
			//
			// DOS image header is not present, TE header is at the image base.
			//
			Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32*)Pe32Data;
			if ((Hdr.Te->Signature == EFI_TE_IMAGE_HEADER_SIGNATURE) &&
				((Hdr.Te->Machine == IMAGE_FILE_MACHINE_I386) || (Hdr.Te->Machine == IMAGE_FILE_MACHINE_IA64) ||
					(Hdr.Te->Machine == IMAGE_FILE_MACHINE_EBC) || (Hdr.Te->Machine == IMAGE_FILE_MACHINE_X64) ||
					(Hdr.Te->Machine == IMAGE_FILE_MACHINE_ARM64) || (Hdr.Te->Machine == IMAGE_FILE_MACHINE_ARMTHUMB_MIXED))
				)
			{
				break;
			}
		}

		//
		// Not found the image base, check the previous aligned address
		//
		Pe32Data -= SIZE_4KB;
	}

	//DEBUG_CODE_END();

	return Pe32Data;
}
#define IMAGE_LOAD_SIGNATURE        SIGNATURE_32('L','O','A','D')
VOID
EFIAPI
PeCoffLoaderRelocateImageExtraActionWindbg(
	IN OUT PE_COFF_LOADER_IMAGE_CONTEXT* ImageContext
)
{
	AsmWriteDr2((UINTN)ImageContext);
	/*AsmWriteDr3((UINTN)ImageContext->ImageSize);
	AsmWriteDr1((UINTN)ImageContext->PdbPointer);*/
	AsmWriteDr0(IMAGE_LOAD_SIGNATURE);
	return;
}


VOID
FindAndReportModuleImageInfo(
	IN WCHAR* exepath
)
{
	UINTN                         Pe32Data;
	PE_COFF_LOADER_IMAGE_CONTEXT* ImageContext = (PE_COFF_LOADER_IMAGE_CONTEXT*)AllocateZeroPool(sizeof(PE_COFF_LOADER_IMAGE_CONTEXT));
	UINT32 CheckSum = 0;
	UINT32 SizeOfImage = 0;
	SHELL_FILE_HANDLE fileHandle=NULL;
	UINT64 fielsize = 0;
	//
	// Find Image Base
	//
	Pe32Data = PeCoffSearchImageBaseWindbg((UINTN)mErrorMsgVersionAlert);
	if (Pe32Data != 0) {
		ImageContext->ImageAddress = Pe32Data;
		if (ForceConsoleOutput)
		{
			Print(L"ImageContext.ImageAddress %p\r\n", ImageContext->ImageAddress);			

		}

		EFI_STATUS efiStatus = ShellOpenFileByName(exepath,
			&fileHandle,
			EFI_FILE_MODE_READ,
			0);
		if (EFI_ERROR(efiStatus))
		{
			Print(L"Failed to open ourselves: %lx\n", efiStatus);
			fileHandle = NULL;
			goto reportsymbol;
		}

		//ImageContext.PdbPointer = PeCoffLoaderGetPdbPointer((VOID*)(UINTN)ImageContext.ImageAddress);
		efiStatus = ShellGetFileSize(fileHandle, &fielsize);
		if (EFI_ERROR(efiStatus))
		{
			Print(L"Failed to ShellGetFileSize: %lx\n", efiStatus);

			goto reportsymbol;
		}
		void* filebuf = AllocateZeroPool(fielsize);

		efiStatus = ShellReadFile(fileHandle, &fielsize, filebuf);

		if (EFI_ERROR(efiStatus))
		{
			Print(L"Failed to ShellReadFile: %lx\n", efiStatus);
			
			goto reportsymbol;
		}
		WCHAR* pdbpath = GetModuleName((UINT8*)filebuf, &CheckSum,&SizeOfImage);
		if (pdbpath)
		{
			if (ForceConsoleOutput)
			{
				KdpDprintf(L"%s\r\n", pdbpath);
			}
			ImageContext->PdbPointer = pdbpath;
			
		}
		if (CheckSum != 0)
		{
			//暂时先用这个
			ImageContext->DebugDirectoryEntryRva = CheckSum;
		}
		if(SizeOfImage!=0)
		{
			ImageContext->ImageSize = SizeOfImage;
		}else
		{
			ImageContext->ImageSize = 0x10000;
		}
		FreePool(filebuf);

reportsymbol:
		if (fileHandle != NULL)
		{
			ShellCloseFile(&fileHandle);
		}

		PeCoffLoaderRelocateImageExtraActionWindbg(ImageContext);
	}
	return;
}




VOID
FindAndReportModuleImageInfoPdb(
	IN UINTN  AlignSize
)
{
	UINTN                         Pe32Data;
	PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;

	//
	// Find Image Base
	//
	UINT32 CheckSum = 0;
	UINT32 SizeOfImage = 0;
	Pe32Data = PeCoffSearchImageBaseWindbg((UINTN)mErrorMsgVersionAlert);
	if (Pe32Data != 0) {
		ImageContext.ImageAddress = Pe32Data;
		if (ForceConsoleOutput)
		{
			Print(L"ImageContext.ImageAddress %p\r\n", ImageContext.ImageAddress);
		}
		__debugbreak();
		//ImageContext.PdbPointer = PeCoffLoaderGetPdbPointer((VOID*)(UINTN)ImageContext.ImageAddress);
		WCHAR* pdbpath = GetModuleName((UINT8*)ImageContext.ImageAddress, &CheckSum,&SizeOfImage);
		if (pdbpath)
		{

			KdpDprintf(L"%s\r\n", pdbpath);
		}
	}
	return;
}
VOID
NTAPI
OutputMsg(_In_ CHAR16* msg)
{
	if(EnableWindbgPluginInitialized)
	{
		pWindbgProtocol->OutputMsg(msg);
	}else
	{
		Print(msg);
	}
	
	return;
}
void DumpRspFunction(UINT64 rspval)
{

}

BOOLEAN EnableWindbgPlugin(WCHAR* exepath)
{
	EFI_STATUS efiStatus = gBS->LocateProtocol(&gEfiWindbgProtocolGUID, NULL, &pWindbgProtocol);
	if (EFI_ERROR(efiStatus))
	{
		Print(L"Failed to locate our windbg plugin: %lx\n", efiStatus);
		return FALSE;
	}
	EnableWindbgPluginInitialized = TRUE;
	OutputMsg(L"EnableWindbgPlugin\r\n");
	FindAndReportModuleImageInfo(exepath);

	
	return TRUE;
}


BOOLEAN DisableWindbgPlugin()
{
	OutputMsg(L"DisableWindbgPlugin\r\n");
	return TRUE;
}


VOID
NTAPI
KdpDprintf(
	_In_ CHAR16* FormatString,
	...)
{

	STRING String;
	UINT64 Length = 0;
	VA_LIST   ap;
	CHAR16* Buffer = NULL;
	/* Format the string */
	VA_START(ap, FormatString);
	Buffer = CatVSPrint(NULL,
		FormatString,
		ap);
	VA_END(ap);
	if (Buffer == 0)
	{
		return;
	}
	Length = StrLen(Buffer);
	if (Length == 0)
	{
		return;
	}

	OutputMsg(Buffer);
	return;
}