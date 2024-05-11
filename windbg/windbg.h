#include "utils.h"


typedef EFI_STATUS(EFIAPI* EFI_OUTPUT_MSG)(CHAR16* msg);


extern EFI_GUID gEfiWindbgProtocolGUID;




typedef struct _EFI_WINDBGPROTOCOL {
	UINT64 Revsion;  //�汾
	EFI_OUTPUT_MSG OutputMsg;  //��Ա����
}EFI_WINDBGPROTOCOL,*PEFI_WINDBGPROTOCOL;



BOOLEAN EnableWindbgPlugin(WCHAR* exepath);