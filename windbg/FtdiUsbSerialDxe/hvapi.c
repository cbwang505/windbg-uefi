
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
#include "hvgdk.h"

typedef void(__fastcall TriggerCall)(UINT64 rcx);




__declspec(align(VSM_PAGE_SIZE)) UINT8 hv_vp_assist_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 hv_hypercall_input_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 hv_hypercall_output_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 hv_hypercall_rsp_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 HvcallCodeVaVTL1_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 SimBaseSimpGpaVtl1[VSM_PAGE_SIZE];
extern UINT64 synic_message_page_val;
extern UINT64 signalflag ;
extern UINT64 signalvalue ;
extern BOOLEAN ForceConsoleOutput;
extern UINT32 gmessageConnectionId;
UINT64 hv_pVmxon = 0;
UINT64 hv_enlvmcs = 0;
UINT64 gapicpage = 0;
UINT64 gapicpagevtl1 = 0;
UINT64 gPartitionId = 0;
UINT64 ghypercall_page = 0;
UINT32 SkiInitialMxCsr = 0x1F80;
static PHV_MESSAGE SimBaseSimpGpa = NULL;
TriggerCall* vtl_call_fn = NULL;
TriggerCall* vtl_ret_fn = NULL;
TriggerCall* vtl_ret_fn_vtl1 = NULL;
typedef HV_STATUS(*HvlInvokeHypercall)(UINT64 InputValue, UINT64 InputPa, UINT64 OutputPa);

HvlInvokeHypercall HvcallCodeVa;
HvlInvokeHypercall HvcallCodeVaVTL1;

HV_STATUS HVHyperCall(UINT64 rcx);

typedef union _HV_X64_MSR_HYPERCALL_DESC {
	struct {
		UINT64		EnableHypercallPage : 1;	// [0] - Enables the hypercall page
		UINT64		Locked : 1;					// [1] - Indicates if this MSR is immutable
		UINT64		Reserved : 10;				// [11:2]
		UINT64		HypercallGPA : 52;			// [63:12] - ndicates the Guest Physical Page Number of the hypercall page
	} Fields;
	UINT64 AsUINT64;
}HV_X64_MSR_HYPERCALL_DESC, * PHV_X64_MSR_HYPERCALL_DESC;

UINT64 hv_acquire_hypercall_input_page(void)
{
	hvresetmemory(hv_hypercall_input_page, VSM_PAGE_SIZE);

	return (UINT64)hv_hypercall_input_page;
}

UINT64 hv_acquire_hypercall_output_page(void)
{
	hvresetmemory(hv_hypercall_output_page, VSM_PAGE_SIZE);

	return (UINT64)hv_hypercall_output_page;
}
static UINT64 hv_acquire_hypercall_rsp_page(void)
{
	hvresetmemory(hv_hypercall_rsp_page, VSM_PAGE_SIZE);

	return (UINT64)hv_hypercall_rsp_page;
}

NTSTATUS NTAPI InitGlobalHv()
{
	HV_X64_MSR_HYPERCALL_DESC HypercallMsr = { 0 };
	HypercallMsr.AsUINT64 = __readmsr(HV_X64_MSR_HYPERCALL);
	if (!HypercallMsr.Fields.EnableHypercallPage || !HypercallMsr.Fields.HypercallGPA)
	{
		KdpDprintf(L"UefiMain!InitGlobalHv HV_X64_MSR_HYPERCALL HV_STATUS_UNKNOWN_PROPERTY!\n");
		return HV_STATUS_UNKNOWN_PROPERTY;
	}
	HvcallCodeVa = (HvlInvokeHypercall)((UINT64)HypercallMsr.Fields.HypercallGPA << VSM_PAGE_SHIFT);
	hvcopymemory((void*)HvcallCodeVaVTL1_page, (void*)HvcallCodeVa, PAGE_SIZE);
	HvcallCodeVaVTL1 = (HvlInvokeHypercall)HvcallCodeVaVTL1_page;
	if (ForceConsoleOutput)
	{
		KdpDprintf(L"UefiMain!InitGlobalHv HvcallCodeVa %016llx!\n", HvcallCodeVa);
	}
	return EFI_SUCCESS;
}
void HvApicSelfIpiVtl0()
{
}

NTSTATUS NTAPI InitGlobalHvVtl1()
{
	return 0;
}

void NTAPI hv_vtl_ap_entry(void)
{

}
NTSTATUS SkpPrepareForReturnToNormalMode(UINT64 rcx, UINT64 rdx)
{

	KdpDprintf(L"UefiMain!SkpPrepareForReturnToNormalMode!\n");

	return 0;
}
NTSTATUS NTAPI HvHvTranslateVirtualAddress(UINT64 gva, UINT64* gpa)
{
	UINT8 buf[0x100];
	hvresetmemory(buf, 0x100);
	UINT64 pvapfn = VSM_PAGE_TO_PFN((UINT64)gva);
	UINT64	hvcallrcx = (UINT64)buf;
	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallTranslateVirtualAddress;
	input->IsFast = 1;
	input->Nested = 0;
	PHV_INPUT_TRANSLATE_VIRTUAL_ADDRESS param = (PHV_INPUT_TRANSLATE_VIRTUAL_ADDRESS)(hvcallrcx + 8);
	param->PartitionId = HV_PARTITION_ID_SELF;
	param->VpIndex = HV_VP_INDEX_SELF;
	param->ControlFlags = HV_TRANSLATE_GVA_VALIDATE_READ | HV_TRANSLATE_GVA_VALIDATE_WRITE;
	param->GvaPage = pvapfn;
	//NTSTATUS ret = HVHyperCall(hvcallrcx);
	NTSTATUS ret = HVHyperCall(hvcallrcx);
	if (!NT_SUCCESS(ret))
		return ret;
	//这个不能用
	//dumpbuf((void*)buf, 0x100);
	size_t outoffset = ALIGN_UP_FIX(sizeof(HV_INPUT_TRANSLATE_VIRTUAL_ADDRESS), 0x10);
	PHV_OUTPUT_TRANSLATE_VIRTUAL_ADDRESS gpaout = (PHV_OUTPUT_TRANSLATE_VIRTUAL_ADDRESS)(hvcallrcx + outoffset);
	HV_TRANSLATE_GVA_RESULT res = gpaout->TranslationResult;
	UINT64 gpapfn = gpaout->GpaPage;
	KdpDprintf(L"hvapi!HvHvTranslateVirtualAddress ret:=> %08x,code:=> %08x,gva:=> %016llx,gpa:=> %016llx!\n", ret, res.ResultCode, gva, gpapfn);

	return ret;
}

NTSTATUS NTAPI HvHvSignalEvent(UINT32 evt)
{
	UINT8 buf[0x100];
	hvresetmemory(buf, 0x100);	
	UINT64	hvcallrcx = (UINT64)buf;
	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallSignalEvent;
	input->IsFast = 1;
	input->Nested = 0;
	PHV_INPUT_SIGNAL_EVENT param = (PHV_INPUT_SIGNAL_EVENT)(hvcallrcx + 8);
	param->ConnectionId.AsUINT32 = evt;
	param->FlagNumber = 0;
	param->RsvdZ = 0;
	//NTSTATUS ret = HVHyperCall(hvcallrcx);
	NTSTATUS ret = HVHyperCall(hvcallrcx);
	if (!NT_SUCCESS(ret))
		return ret;
	//这个不能用
	
	//KdpDprintf(L"hvapi!HvHvSignalEvent ret:=> %08x!\n", ret);

	return ret;
}



BOOLEAN NTAPI HvMemoryReadPresent(UINT64 gva)
{

	BOOLEAN MemoryFound = FALSE;
	UINT8 buf[0x100];
	hvresetmemory(buf, 0x100);
	UINT64 pvapfn = VSM_PAGE_TO_PFN((UINT64)gva);
	UINT64	hvcallrcx = (UINT64)buf;
	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallTranslateVirtualAddress;
	input->IsFast = 1;
	input->Nested = 0;
	PHV_INPUT_TRANSLATE_VIRTUAL_ADDRESS param = (PHV_INPUT_TRANSLATE_VIRTUAL_ADDRESS)(hvcallrcx + 8);
	param->PartitionId = HV_PARTITION_ID_SELF;
	param->VpIndex = HV_VP_INDEX_SELF;
	param->ControlFlags = HV_TRANSLATE_GVA_VALIDATE_READ;
	param->GvaPage = pvapfn;
	//NTSTATUS ret = HVHyperCall(hvcallrcx);
	NTSTATUS ret = HVHyperCall(hvcallrcx);
	if (!NT_SUCCESS(ret))
	{
		return MemoryFound;
	}
	//这个不能用
	//dumpbuf((void*)buf, 0x100);
	size_t outoffset = ALIGN_UP_FIX(sizeof(HV_INPUT_TRANSLATE_VIRTUAL_ADDRESS), 0x10);
	PHV_OUTPUT_TRANSLATE_VIRTUAL_ADDRESS gpaout = (PHV_OUTPUT_TRANSLATE_VIRTUAL_ADDRESS)(hvcallrcx + outoffset);
	HV_TRANSLATE_GVA_RESULT res = gpaout->TranslationResult;
	UINT64 gpapfn = gpaout->GpaPage;

	if(gpapfn==0)
	{
		return MemoryFound;
	}

	if(res.ResultCode== HvTranslateGvaSuccess)
	{
		return TRUE;
	}
	if(FlagOn(res.ResultCode, HvTranslateGvaGpaNoReadAccess)|| FlagOn(res.ResultCode, HvTranslateGvaPageNotPresent)|| FlagOn(res.ResultCode, HvTranslateGvaGpaUnmapped)|| FlagOn(res.ResultCode, HvTranslateGvaPrivilegeViolation)|| FlagOn(res.ResultCode, HvTranslateGvaInvalidPageTableFlags))
	{
		return MemoryFound;
	}
	MemoryFound= TRUE;
	return MemoryFound;

}


BOOLEAN  NTAPI HvMemoryDump(UINT64 gva)
{
	UINT8 buf[0x100];
	hvresetmemory(buf, 0x100);
	UINT64 pvapfn = VSM_PAGE_TO_PFN((UINT64)gva);
	UINT64	hvcallrcx = (UINT64)buf;
	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallTranslateVirtualAddress;
	input->IsFast = 1;
	input->Nested = 0;
	PHV_INPUT_TRANSLATE_VIRTUAL_ADDRESS param = (PHV_INPUT_TRANSLATE_VIRTUAL_ADDRESS)(hvcallrcx + 8);
	param->PartitionId = HV_PARTITION_ID_SELF;
	param->VpIndex = HV_VP_INDEX_SELF;
	param->ControlFlags = HV_TRANSLATE_GVA_VALIDATE_READ | HV_TRANSLATE_GVA_VALIDATE_WRITE;
	param->GvaPage = pvapfn;
	//NTSTATUS ret = HVHyperCall(hvcallrcx);
	NTSTATUS ret = HVHyperCall(hvcallrcx);
	if (!NT_SUCCESS(ret))
	{
		return FALSE;
	}
	//这个不能用
	//dumpbuf((void*)buf, 0x100);
	size_t outoffset = ALIGN_UP_FIX(sizeof(HV_INPUT_TRANSLATE_VIRTUAL_ADDRESS), 0x10);
	PHV_OUTPUT_TRANSLATE_VIRTUAL_ADDRESS gpaout = (PHV_OUTPUT_TRANSLATE_VIRTUAL_ADDRESS)(hvcallrcx + outoffset);
	HV_TRANSLATE_GVA_RESULT res = gpaout->TranslationResult;
	UINT64 gpapfn = gpaout->GpaPage;
	KdpDprintf(L"hvapi!HvHvTranslateVirtualAddress ret:=> %08x,code:=> %08x,gva:=> %016llx,gpa:=> %016llx!\r\n", ret, res.ResultCode, gva, gpapfn);

	return TRUE;

}






NTSTATUS NTAPI HvHvCallPostMessageVtl0(void* buffer, UINT32 buflen)
{

	UINT64	hvcallrdx = hv_acquire_hypercall_input_page();
	UINT64	hvcallr8 = hv_acquire_hypercall_output_page();
	HV_X64_HYPERCALL_INPUT input = { 0 };
	input.AsUINT64 = 0;
	input.CallCode = HvCallPostMessage;
	input.IsFast = 0;
	input.Nested = 0;



	PHV_INPUT_POST_MESSAGE param1 = (PHV_INPUT_POST_MESSAGE)hvcallrdx;
	param1->ConnectionId.Id = gmessageConnectionId;
	param1->MessageType = 1;
	param1->Reserved = 0;
	param1->PayloadSize = buflen;

	hvcopymemory(param1->Payload, buffer, buflen);

	//dumpbuf(hvcallrdx, 0x100);
	NTSTATUS ret = HvcallCodeVa(input.AsUINT64, hvcallrdx, hvcallr8);

	if (!NT_SUCCESS(ret))
		return ret;

	KdpDprintf(L"UefiMain!  HvHvCallPostMessage ret:=> %08x!\r\n", ret);

	return ret;
}





NTSTATUS NTAPI HvHvCallPostMessageVtl0MessageType(void* buffer, UINT32 buflen, UINT32 MessageType)
{

	UINT64	hvcallrdx = hv_acquire_hypercall_input_page();
	UINT64	hvcallr8 = hv_acquire_hypercall_output_page();
	HV_X64_HYPERCALL_INPUT input = { 0 };
	input.AsUINT64 = 0;
	input.CallCode = HvCallPostMessage;
	input.IsFast = 0;
	input.Nested = 0;



	PHV_INPUT_POST_MESSAGE param1 = (PHV_INPUT_POST_MESSAGE)hvcallrdx;
	param1->ConnectionId.Id = gmessageConnectionId;
	param1->MessageType = MessageType;
	param1->Reserved = 0;
	param1->PayloadSize = buflen;

	hvcopymemory(param1->Payload, buffer, buflen);

	//dumpbuf(hvcallrdx, 0x100);
	NTSTATUS ret = HvcallCodeVa(input.AsUINT64, hvcallrdx, hvcallr8);

	if (!NT_SUCCESS(ret))
		return ret;

	KdpDprintf(L"UefiMain!  HvHvCallPostMessage ret:=> %08x!\r\n", ret);

	return ret;
}