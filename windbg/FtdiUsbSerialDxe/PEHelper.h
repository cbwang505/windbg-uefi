#ifndef __PI_PE_H__
#define __PI_PE_H__

#include <IndustryStandard/PeImage.h>

#define CV_SIGNATURE_NB10	'01BN'
#define CV_SIGNATURE_NB09	'90BN'

typedef struct _CV_HEADER
{
	DWORD dwSignature;
	DWORD dwOffset;
}CV_HEADER, * PCV_HEADER;
typedef struct _CV_INFO_PDB20
{
	CV_HEADER CvHeader;
	DWORD dwSignature;
	DWORD dwAge;
	BYTE PdbFileName[];
}CV_INFO_PDB20, * PCV_INFO_PDB20;
/************************************************************************/
/*  Member				|Description
 *  CvHeader.Signature	|CodeView signature, equal to ¡°NB10¡±
 *  CvHeader.Offset		|CodeView offset. Set to 0, because debug information is stored in a separate file.
 *  Signature			|The time when debug information was created (in seconds since 01.01.1970)
 *  Age					|Ever-incrementing value, which is initially set to 1 and incremented every time when a part of the PDB file is updated without rewriting the whole file.
 *  PdbFileName			|Null-terminated name of the PDB file. It can also contain full or partial path to the file.                                                                    */
 /************************************************************************/

#define CV_SIGNATURE_RSDS   'SDSR'

typedef struct _CV_INFO_PDB70
{
	DWORD dwHeader;
	GUID  Signature;
	DWORD dwAge;
	CHAR  PdbFileName[1];
} CV_INFO_PDB70, * PCV_INFO_PDB70;
/*
 * Member			|Description
 * CvSignature		|CodeView signature, equal to ¡°RSDS¡±
 * Signature		|A unique identifier, which changes with every rebuild of the executable and PDB file.
 * Age				|Ever-incrementing value, which is initially set to 1 and incremented every time when a part of the PDB file is updated without rewriting the whole file.
 * PdbFileName		|Null-terminated name of the PDB file. It can also contain full or partial path to the file.
 */

typedef struct _IMAGE_DEBUG_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Type;
	DWORD   SizeOfData;
	DWORD   AddressOfRawData;
	DWORD   PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, * PIMAGE_DEBUG_DIRECTORY;

VOID InternalClean();

#define IMAGE_DOS_SIGNATURE			0x5a4d     /* MZ   */
#define IMAGE_NT_SIGNATURE			0x00004550 /* PE00 */

/* machine type */

#define	IMAGE_FILE_MACHINE_AMD64	0x8664


#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b

#endif