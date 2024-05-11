
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

#include "PEHelper.h"




void  InternalClean()
{
	
}

UINT64 RVAToFOA(DWORD ulRva, LPVOID m_pNtHeader, EFI_IMAGE_FILE_HEADER* m_pImageFileHeader)
{
	if (m_pNtHeader && m_pImageFileHeader)
	{
		EFI_IMAGE_SECTION_HEADER* pImageSectionHeader =
			((EFI_IMAGE_SECTION_HEADER*)((ULONG_PTR)(m_pImageFileHeader)+sizeof(EFI_IMAGE_FILE_HEADER) + m_pImageFileHeader->SizeOfOptionalHeader));

		// 遍历节表，查找目标RVA所属的节表，并且算出FOA
		for (int i = 0; i < m_pImageFileHeader->NumberOfSections; i++)
		{
			if ((ulRva >= pImageSectionHeader[i].VirtualAddress) &&
				(ulRva <= pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData))
			{
				return pImageSectionHeader[i].PointerToRawData + (ulRva - pImageSectionHeader[i].VirtualAddress);
			}
		}
	}

	return 0;
}
static  UINT64 PtrToUlonglong(const void* p)
{
	return (UINT64)p;
}
static void* ULonglongToPtr(ULONG64 ul)
{
	return (void*)ul;
}

#define IfFalseGoExit(x) { br=(x); if (!br) goto _Error; }

//************************************
// Method:    GetPDBFilePath
// FullName:  GetPDBFilePath
// Access:    public 
// Returns:   VOID
// Qualifier:
// Parameter: char* & strPdbPath
//			 从PE文件中读取调试信息中的PDB信息(如果存在)
//************************************
WCHAR* GetPDBInfo(UINT8* m_pBuffer, UINT32* m_pCheckSum, UINT32* m_pSizeOfImage)
{

	EFI_IMAGE_DOS_HEADER* m_pImageDosHeader = (EFI_IMAGE_DOS_HEADER*)(m_pBuffer);
	BOOLEAN br = FALSE;

	EFI_IMAGE_FILE_HEADER* m_pImageFileHeader;
	//LPVOID pNtHeaders = NULL;
	DWORD dwE_lfanew = 0;
	DWORD dwPESignature = 0;
	UINT64 ulAddressTemp = 0;
	int m_dwMchine = 0;
	UINT8* m_pNtHeader = NULL;
	// 对比MZ签名	
	IfFalseGoExit(IMAGE_DOS_SIGNATURE == m_pImageDosHeader->e_magic);

	// 对比PE签名
	dwE_lfanew = m_pImageDosHeader->e_lfanew & 0x0ffff;
	ulAddressTemp = PtrToUlonglong(m_pBuffer) + dwE_lfanew;

	dwPESignature = *((PDWORD)ULonglongToPtr(ulAddressTemp));
	IfFalseGoExit(IMAGE_NT_SIGNATURE == dwPESignature);

	// 因为还不确定是PE32或PE64，所以先保存IMAGE_NT_HEADER的地址
	m_pNtHeader = (UINT8*)ulAddressTemp;

	// 获取IMAGE_FILE_HEADER，然后判断目标平台CPU类型
	ulAddressTemp = ulAddressTemp + sizeof(IMAGE_NT_SIGNATURE);
	m_pImageFileHeader = (EFI_IMAGE_FILE_HEADER*)ULonglongToPtr(ulAddressTemp);

	if (IMAGE_FILE_MACHINE_I386 == m_pImageFileHeader->Machine)
	{
		// 初步判断为PE32，继续检测OptionalHeader中的Magic
		EFI_IMAGE_NT_HEADERS32* pImageNtHeader32 =
			(EFI_IMAGE_NT_HEADERS32*)m_pNtHeader;

		IfFalseGoExit(
			IMAGE_NT_OPTIONAL_HDR32_MAGIC == pImageNtHeader32->OptionalHeader.Magic);
		// 确定为PE32
		m_dwMchine = IMAGE_FILE_MACHINE_I386;
	}
	else if (IMAGE_FILE_MACHINE_AMD64 == m_pImageFileHeader->Machine)
	{
		// 初步判断为PE64，继续检测OptionalHeader中的Magic
		EFI_IMAGE_NT_HEADERS64* pImageNtHeader64 =
			(EFI_IMAGE_NT_HEADERS64*)m_pNtHeader;

		IfFalseGoExit(
			IMAGE_NT_OPTIONAL_HDR64_MAGIC == pImageNtHeader64->OptionalHeader.Magic);
		// 确定为PE64
		m_dwMchine = IMAGE_FILE_MACHINE_AMD64;
	}
	else
	{
		// 不支持的类型
		IfFalseGoExit(FALSE);
	}

	
	
	//char* strPDBSignature;
	//DWORD dwPDBAge = 0;
	if (NULL == m_pNtHeader)
	{
		return NULL;
	}
	char* strFileNameA = NULL;
	ULONG ulDebugDirectoryRVA = 0;
	int nDirectoryItemCount = 0;

	if (IMAGE_FILE_MACHINE_I386 == m_dwMchine)
	{
		EFI_IMAGE_NT_HEADERS32* pImageNtHeader32 =
			(EFI_IMAGE_NT_HEADERS32*)m_pNtHeader;

		ulDebugDirectoryRVA = 
			pImageNtHeader32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
		DWORD dwSize = 
			pImageNtHeader32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

		nDirectoryItemCount = dwSize / sizeof(IMAGE_DEBUG_DIRECTORY);

		*m_pCheckSum = pImageNtHeader32->OptionalHeader.CheckSum;
		*m_pSizeOfImage = pImageNtHeader32->OptionalHeader.SizeOfImage;
	}
	else if(IMAGE_FILE_MACHINE_AMD64 == m_dwMchine)
	{
		EFI_IMAGE_NT_HEADERS64* pImageNtHeader64 =
			(EFI_IMAGE_NT_HEADERS64*)m_pNtHeader;

		ulDebugDirectoryRVA = 
			pImageNtHeader64->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
		DWORD dwSize = 
			pImageNtHeader64->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

		nDirectoryItemCount = dwSize / sizeof(IMAGE_DEBUG_DIRECTORY);
		*m_pCheckSum = pImageNtHeader64->OptionalHeader.CheckSum;
		*m_pSizeOfImage = pImageNtHeader64->OptionalHeader.SizeOfImage;
	}
	else
	{
		return NULL;
	}

	UINT64 ulDebugDirectoryFOA = RVAToFOA(ulDebugDirectoryRVA, m_pNtHeader, m_pImageFileHeader) + (UINT64)m_pImageDosHeader;

	PIMAGE_DEBUG_DIRECTORY pImageDebugDirectory =
		(PIMAGE_DEBUG_DIRECTORY)ULonglongToPtr(ulDebugDirectoryFOA);

	for (int i=0; i<nDirectoryItemCount; i++)
	{
		if (EFI_IMAGE_DEBUG_TYPE_CODEVIEW == pImageDebugDirectory[i].Type)
		{
			PVOID pDebugInfoRawData = 
				(PVOID) ((ULONG_PTR)m_pImageDosHeader + pImageDebugDirectory[i].PointerToRawData);

			if (pDebugInfoRawData)
			{
				DWORD dwCvSignature = 
					*((PDWORD) pDebugInfoRawData);

				//char* strSignature;
				//char* strFileName;
				DWORD dwAge = 0;

				switch (dwCvSignature)
				{
				case CV_SIGNATURE_NB09:
				case CV_SIGNATURE_NB10:
					{
						PCV_INFO_PDB20 pCvInfoPdb = 
							((PCV_INFO_PDB20) pDebugInfoRawData);

						/*strSignature.Format(
							_T("%08X"),
							pCvInfoPdb->dwSignature);*/

						strFileNameA = pCvInfoPdb->PdbFileName;
						
						dwAge = pCvInfoPdb->dwAge;
						break;
					}
					
				case CV_SIGNATURE_RSDS:
					{
						PCV_INFO_PDB70 pCvInfoPdb = 
							((PCV_INFO_PDB70) pDebugInfoRawData);

						/*strSignature.Format(
							_T("%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X"),
							pCvInfoPdb->Signature.Data1, pCvInfoPdb->Signature.Data2, pCvInfoPdb->Signature.Data3,
							pCvInfoPdb->Signature.Data4[0], pCvInfoPdb->Signature.Data4[1],			
							pCvInfoPdb->Signature.Data4[2], pCvInfoPdb->Signature.Data4[3],			
							pCvInfoPdb->Signature.Data4[4], pCvInfoPdb->Signature.Data4[5],			
							pCvInfoPdb->Signature.Data4[6], pCvInfoPdb->Signature.Data4[7]);*/

						strFileNameA = pCvInfoPdb->PdbFileName;
						

						dwAge = pCvInfoPdb->dwAge;
						break;
					}
					break;
				default:
					break;
				}

				
			}
		}
	}
	if(strFileNameA!=NULL)
	{

		
		//Print(L"fid strFileNameA %a\r\n", strFileNameA);
		return CatSPrint(NULL, L"%a", strFileNameA);
	}

_Error:
	InternalClean();
	return NULL;
}



WCHAR* GetModulePdbFileName(UINT8* m_pBuffer, UINT32* m_pCheckSum, UINT32* m_pSizeOfImage)
{

	WCHAR* pdbpath = GetPDBInfo(m_pBuffer, m_pCheckSum, m_pSizeOfImage);
	if(pdbpath)
	{
		WCHAR* savepat = pdbpath;
		WCHAR* tmppath = StrStr(pdbpath, L"\\");
		tmppath++;
		while (tmppath)
		{
			savepat = tmppath;
			pdbpath = tmppath;
			tmppath = StrStr(pdbpath, L"\\");
			if(!tmppath)
			{
				break;
			}
			tmppath++;
		}
		return savepat;
	}

	return NULL;
}



WCHAR* GetModuleName(UINT8* m_pBuffer, UINT32* m_pCheckSum, UINT32* m_pSizeOfImage)
{

	WCHAR* pdbpath = GetModulePdbFileName(m_pBuffer, m_pCheckSum, m_pSizeOfImage);
	if (pdbpath)
	{
		UINT64 pathlen = StrLen(pdbpath);
		for (UINT64 i=1;i< pathlen;i++)
		{
			WCHAR chktmp = pdbpath[i];
			if(chktmp==L'.')
			{
				pdbpath[i] = L'\0';
			}
			StrCatS(pdbpath, pathlen+1, L".efi");
		}
		
		return pdbpath;
	}

	return NULL;
}