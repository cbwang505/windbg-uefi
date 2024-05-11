/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

	shvos.c

Abstract:

	This module implements the OS-facing UEFI stubs for SimpleVisor.

Author:

	Alex Ionescu (@aionescu) 29-Aug-2016 - Initial version

Environment:

	Kernel mode only.

--*/

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
#include <Library/PeCoffExtraActionLib.h>

//
// Shell Library
//
#include <Library/ShellLib.h>

// 
// Custom Driver Protocol 
// 
#include "../UefiDriver/drvproto.h"
#include "stdint.h"

#include "apic-defs.h"
#include "registers.h"
#include "windbg.h"
#include "hvgdk.h"
#include <intrin.h>

__declspec(align(VSM_PAGE_SIZE)) UINT8 hv_vp_assist_page[VSM_PAGE_SIZE];

__declspec(align(VSM_PAGE_SIZE)) UINT8 hv_hypercall_input_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 hv_hypercall_output_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 hv_hypercall_rsp_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 HvcallCodeVaVTL1_page[VSM_PAGE_SIZE];

__declspec(align(VSM_PAGE_SIZE)) UINT8 SimBaseSimpGpaVtl1[VSM_PAGE_SIZE];


BOOLEAN ForceConsoleOutput = FALSE;
void HvVmbusNegotiateVersion();
void HvVmbusRequestOffers();
void HvVmbusRequestOfferstest();
NTSTATUS HvSYNICVtl0();
HV_STATUS HVHyperCall(UINT64 rcx);
HV_STATUS HV_VTL_AP_ENTRY_HANDLER(UINT64 rcx);
void dumpbuf(void* buf, int len);
void
hvresetmemory(
	void* dest,
	UINT32  count
);
void*
hvcopymemory(
	void* dest,
	void* src,
	UINT32  count
);
typedef HV_STATUS(*HvlInvokeHypercall)(UINT64 InputValue, UINT64 InputPa, UINT64 OutputPa);

HvlInvokeHypercall HvcallCodeVa;
HvlInvokeHypercall HvcallCodeVaVTL1;

typedef void(__fastcall TriggerCall)(UINT64 rcx);
void  ShvlpVtlCall(UINT64 rcx);
void CpuSleep();
//
// We run on any UEFI Specification
//
extern CONST UINT32 _gUefiDriverRevision = 0;
TriggerCall* vtl_call_fn = NULL;
TriggerCall* vtl_ret_fn = NULL;
UINT64 hv_pVmxon = 0;
UINT64 hv_enlvmcs = 0;
UINT64 gapicpage = 0;
UINT64 gapicpagevtl1 = 0;
UINT64 gPartitionId = 0;
UINT64 ghypercall_page = 0;
UINT32 SkiInitialMxCsr = 0x1F80;
static PHV_MESSAGE SimBaseSimpGpa = NULL;

typedef union _CR0 {
	struct {
		uint32_t PE : 1;           ///< Protection Enable.
		uint32_t MP : 1;           ///< Monitor Coprocessor.
		uint32_t EM : 1;           ///< Emulation.
		uint32_t TS : 1;           ///< Task Switched.
		uint32_t ET : 1;           ///< Extension Type.
		uint32_t NE : 1;           ///< Numeric Error.
		uint32_t : 10;            ///< Reserved.
		uint32_t WP : 1;           ///< Write Protect.
		uint32_t : 1;             ///< Reserved.
		uint32_t AM : 1;           ///< Alignment Mask.
		uint32_t : 10;            ///< Reserved.
		uint32_t NW : 1;           ///< Mot Write-through.
		uint32_t CD : 1;           ///< Cache Disable.
		uint32_t PG : 1;           ///< Paging.
	}Fields;
	UINT64 AsUINT64;
}  CR0, * PCR0;

typedef union  _CR4 {
	struct {
		uint32_t VME : 1;          ///< Virtual-8086 Mode Extensions.
		uint32_t PVI : 1;          ///< Protected-Mode Virtual Interrupts.
		uint32_t TSD : 1;          ///< Time Stamp Disable.
		uint32_t DE : 1;           ///< Debugging Extensions.
		uint32_t PSE : 1;          ///< Page Size Extensions.
		uint32_t PAE : 1;          ///< Physical Address Extension.
		uint32_t MCE : 1;          ///< Machine Check Enable.
		uint32_t PGE : 1;          ///< Page Global Enable.
		uint32_t PCE : 1;          ///< Performance Monitoring Counter
								 ///< Enable.
		uint32_t OSFXSR : 1;       ///< Operating System Support for
								 ///< FXSAVE and FXRSTOR instructions
		uint32_t OSXMMEXCPT : 1;   ///< Operating System Support for
								 ///< Unmasked SIMD Floating Point
								 ///< Exceptions.
		uint32_t UMIP : 1;         ///< User-Mode Instruction Prevention.
		uint32_t LA57 : 1;         ///< Linear Address 57bit.
		uint32_t VMXE : 1;         ///< VMX Enable.
		uint32_t SMXE : 1;         ///< SMX Enable.
		uint32_t : 1;             ///< Reserved.
		uint32_t FSGSBASE : 1;     ///< FSGSBASE Enable.
		uint32_t PCIDE : 1;        ///< PCID Enable.
		uint32_t OSXSAVE : 1;      ///< XSAVE and Processor Extended States Enable.
		uint32_t : 1;             ///< Reserved.
		uint32_t SMEP : 1;         ///< SMEP Enable.
		uint32_t SMAP : 1;         ///< SMAP Enable.
		uint32_t PKE : 1;          ///< Protection-Key Enable.
		uint32_t CET : 1;          ///< Control-flow Enforcement Technology
		uint32_t PKS : 1;          ///< Enable Protection Keys for Supervisor-Mode Pages
		uint32_t Reserved : 7;             ///< Reserved.
	}Fields;
	UINT64 AsUINT64;
} CR4, * PCR4;

typedef union _MSR_IA32_APIC_BASE_REGISTER {
	///
	/// Individual bit fields
	///
	struct {
		UINT32  Reserved1 : 8;
		///
		/// [Bit 8] BSP flag (R/W).
		///
		UINT32  BSP : 1;
		UINT32  Reserved2 : 1;
		///
		/// [Bit 10] Enable x2APIC mode. Introduced at Display Family / Display
		/// Model 06_1AH.
		///
		UINT32  EXTD : 1;
		///
		/// [Bit 11] APIC Global Enable (R/W).
		///
		UINT32  EN : 1;
		///
		/// [Bits 31:12] APIC Base (R/W).
		///
		UINT32  ApicBase : 20;
		///
		/// [Bits 63:32] APIC Base (R/W).
		///
		UINT32  ApicBaseHi : 32;
	} Bits;
	///
	/// All bit fields as a 64-bit value
	///
	UINT64  Uint64;
} MSR_IA32_APIC_BASE_REGISTER, PMSR_IA32_APIC_BASE_REGISTER;
typedef union {
	struct {
		UINT32  Vector : 8;          ///< The vector number of the interrupt being sent.
		UINT32  Reserved0 : 4;       ///< Reserved.
		UINT32  DeliveryStatus : 1;  ///< 0: Idle, 1: send pending.
		UINT32  Reserved1 : 3;       ///< Reserved.
		UINT32  Mask : 1;            ///< 0: Not masked, 1: Masked.
		UINT32  TimerMode : 1;       ///< 0: One-shot, 1: Periodic.
		UINT32  Reserved2 : 14;      ///< Reserved.
	} Bits;
	UINT32    Uint32;
} LOCAL_APIC_LVT_TIMER;

typedef union _HV_X64_MSR_HYPERCALL_DESC {
	struct {
		UINT64		EnableHypercallPage : 1;	// [0] - Enables the hypercall page
		UINT64		Locked : 1;					// [1] - Indicates if this MSR is immutable
		UINT64		Reserved : 10;				// [11:2]
		UINT64		HypercallGPA : 52;			// [63:12] - ndicates the Guest Physical Page Number of the hypercall page
	} Fields;
	UINT64 AsUINT64;
}HV_X64_MSR_HYPERCALL_DESC, * PHV_X64_MSR_HYPERCALL_DESC;

typedef union hv_x64_msr_contents
{
	UINT64 as_uint64;
	struct
	{
		UINT64 enable : 1;
		UINT64 reserved : 11;
		UINT64 guest_physical_address : 52;
	} u;
} hv_msr_contents;


typedef union hv_register_vsm_code_page_offsets {
	UINT64 as_u64;

	struct {
		UINT64 vtl_call_offset : 12;
		UINT64 vtl_return_offset : 12;
		UINT64 reserved_z : 40;
	}u;
}hv_vsm_code_page_offsets;

typedef union hv_x64_msr_vp_assist_page_contents {
	UINT64 as_uint64;

	struct {
		UINT64 enable : 1;
		UINT64 reserved : 11;
		UINT64 vp_assist_page_base_address : 52;
	} u;
} hv_msr_vp_assist_page_contents;

typedef union _IA32_VMX_BASIC_MSR
{
	UINT64 All;
	struct
	{
		UINT32 RevisionIdentifier : 31;   // [0-30]
		UINT32 Reserved1 : 1;             // [31]
		UINT32 RegionSize : 12;           // [32-43]
		UINT32 RegionClear : 1;           // [44]
		UINT32 Reserved2 : 3;             // [45-47]
		UINT32 SupportedIA64 : 1;         // [48]
		UINT32 SupportedDualMoniter : 1;  // [49]
		UINT32 MemoryType : 4;            // [50-53]
		UINT32 VmExitReport : 1;          // [54]
		UINT32 VmxCapabilityHint : 1;     // [55]
		UINT32 Reserved3 : 8;             // [56-63]
	} Fields;
} IA32_VMX_BASIC_MSR, * PIA32_VMX_BASIC_MSR;
#define DEBUG_LOAD_IMAGE_METHOD_SOFT_INT3         2
const UINT8 _gPcd_FixedAtBuild_PcdDebugLoadImageMethod = DEBUG_LOAD_IMAGE_METHOD_SOFT_INT3;
EFI_GUID gEfiSampleDriverProtocolGuid = EFI_SAMPLE_DRIVER_PROTOCOL_GUID;


//
// Our name
//
CHAR8* gEfiCallerBaseName = "ShellSample";

/*
/* Compare bytes in two buffers. #1#
static int
gmemcmp(
	const void* buf1,
	const void* buf2,
	UINT32      count
)
{
	return (int)CompareMem(buf1, buf2, count);
}*/
UINT8
EFIAPI
IoRead8(
	IN      UINTN  Port
)
{
	return 0;
}
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
	hvresetmemory(hv_hypercall_rsp_page,VSM_PAGE_SIZE);

	return (UINT64)hv_hypercall_rsp_page;
}


NTSTATUS HvSYNICVtl1()
{
	NTSTATUS ret = STATUS_SUCCESS;
	HV_SYNIC_SIMP SimpVal = { 0 };
	SimpVal.AsUINT64 = __readmsr(HvSyntheticMsrSimp);


	UINT64 SiefpVal = __readmsr(HvSyntheticMsrSiefp);



	UINT64 SControlVal = __readmsr(HvSyntheticMsrSControl);

	if (TRUE)
	{
		SimpVal.BaseSimpGpa = VSM_PAGE_TO_PFN((UINT64)SimBaseSimpGpaVtl1);
		SimpVal.SimpEnabled = 1;
		__writemsr(HvSyntheticMsrSimp, SimpVal.AsUINT64);

	}


	return ret;
}



BOOLEAN HvActivateVpPages()
{
	IA32_VMX_BASIC_MSR VmxBasicMsr = { 0 };
	hvresetmemory(hv_pVmxon,VSM_PAGE_SIZE);

	VmxBasicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);
	KdpDprintf(L"UefiMain! MSR_IA32_VMX_BASIC :=> %016llx\n", VmxBasicMsr.All);
	*(UINT64*)hv_pVmxon = VmxBasicMsr.Fields.RevisionIdentifier;
	BOOLEAN Vmxon = __vmx_on(&hv_pVmxon);
	if (Vmxon)
	{
		KdpDprintf(L"UefiMain!Executing Vmxon instruction failed with status : %d\n, hv_pVmxon:=> %016llx!\n", Vmxon, hv_pVmxon);
		return FALSE;
	}

	return TRUE;
}

//检测Bios是否开启VT
BOOLEAN VmxIsCheckSupportVTBIOS()
{
	UINT64 value = __readmsr(IA32_FEATURE_CONTROL_MSR);

	return (value & 0x5) == 0x5;
}


//检测CPU是否支持VT
BOOLEAN VmxIsCheckSupportVTCPUID()
{
	int cpuidinfo[4];
	__cpuidex(cpuidinfo, 1, 0);
	//CPUID 是否支持VT ecx.vmx第6位 如果为1，支持VT，否则不支持
	return (cpuidinfo[2] >> 5) & 1;
}


BOOLEAN hv_init_vmxe()
{
	if(!VmxIsCheckSupportVTCPUID())
	{
		KdpDprintf(L"UefiMain!Executing VmxIsCheckSupportVTCPUID\n");
		return FALSE;
	}

	if (!VmxIsCheckSupportVTBIOS())
	{
		KdpDprintf(L"UefiMain!Executing VmxIsCheckSupportVTBIOS\n" );
		return FALSE;
	}

	CR0 cr0valk = { 0 };
	cr0valk.AsUINT64 = __readcr0();
	KdpDprintf(L"UefiMain!Executing cr0valk Fields __readcr0 with val : %016llx, PG : %016llx ,PE : %016llx\n", cr0valk.AsUINT64,cr0valk.Fields.PG, cr0valk.Fields.PE);
	cr0valk.Fields.PG = 1;
	cr0valk.Fields.PE = 1;
	__writecr0(cr0valk.AsUINT64);
	cr0valk.AsUINT64 = __readcr0();
	KdpDprintf(L"UefiMain!Executing cr0valk Fields __readcr0 with val : %016llx\n", cr0valk.AsUINT64);
	CR4 cr4valk = { 0 };
	cr4valk.AsUINT64 = __readcr4();
	KdpDprintf(L"UefiMain!Executing cr4valk Fields __readcr4 val : %016llx,with VMXE : %016llx\n", cr4valk.AsUINT64, cr4valk.Fields.VMXE);
	cr4valk.Fields.VMXE = 1;
	__writecr4(cr4valk.AsUINT64);
	cr4valk.AsUINT64 = __readcr4();
	KdpDprintf(L"UefiMain!Executing cr4valk Fields __readcr4 with val : %016llx\n", cr4valk.AsUINT64);
	if(cr4valk.Fields.VMXE)
	{
		return TRUE;
	}
	
	return FALSE;
}
BOOLEAN hv_init_vp_assist_page()
{
	UINT64 vp_assist_pfn;
	hvresetmemory(hv_enlvmcs, VSM_PAGE_SIZE);
	hv_msr_vp_assist_page_contents vp_assist_page_msr;

	vp_assist_pfn = VSM_PAGE_TO_PFN((UINT64)hv_vp_assist_page);
	vp_assist_page_msr.u.enable = 1;
	vp_assist_page_msr.u.reserved = 0;
	vp_assist_page_msr.u.vp_assist_page_base_address = vp_assist_pfn;
	PHV_VP_ASSIST_PAGE  pHvVpPage = (PHV_VP_ASSIST_PAGE)hv_vp_assist_page;
	pHvVpPage->EnlightenVmEntry = TRUE;
	pHvVpPage->CurrentNestedVmcs = hv_enlvmcs;
	__writemsr(HV_X64_MSR_APIC_ASSIST_PAGE, vp_assist_page_msr.as_uint64);
	KdpDprintf(L"UefiMain! HV_X64_MSR_APIC_ASSIST_PAGE  vp_assist_page_msr:=> %016llx,hv_vp_assist_page:=> %016llx!\n", vp_assist_page_msr.as_uint64, hv_vp_assist_page);

}


BOOLEAN hv_run_vmxe()
{

	int Vmclear = 0;
	Vmclear = __vmx_vmclear(&hv_enlvmcs);

	if (Vmclear)
	{
		KdpDprintf(L"Executing __vmx_vmclear instruction failed with status : %d\n", Vmclear);
		__vmx_off();
		return FALSE;
	}

	__vmx_vmlaunch();

	__vmx_off();

}
NTSTATUS InitGlobalHv()
{
	HV_X64_MSR_HYPERCALL_DESC HypercallMsr = { 0 };
	HypercallMsr.AsUINT64 = __readmsr(HV_X64_MSR_HYPERCALL);
	if (!HypercallMsr.Fields.EnableHypercallPage || !HypercallMsr.Fields.HypercallGPA)
	{
		KdpDprintf(L"UefiMain!InitGlobalHv HV_X64_MSR_HYPERCALL HV_STATUS_UNKNOWN_PROPERTY!\n");
		return HV_STATUS_UNKNOWN_PROPERTY;
	}
	HvcallCodeVa = (HvlInvokeHypercall)((UINT64)HypercallMsr.Fields.HypercallGPA << VSM_PAGE_SHIFT);
	hvcopymemory(HvcallCodeVaVTL1_page, HvcallCodeVa, PAGE_SIZE);
	HvcallCodeVaVTL1 = HvcallCodeVaVTL1_page;
	if (ForceConsoleOutput)
	{
		KdpDprintf(L"UefiMain!InitGlobalHv HvcallCodeVa %016llx!\n", HvcallCodeVa);
	}
}

NTSTATUS InitGlobalHvVtl1()
{
	__writemsr(HV_X64_MSR_GUEST_OS_ID, 0x8100000000000000);

	HV_X64_MSR_HYPERCALL_DESC HypercallMsr = { 0 };
	HypercallMsr.AsUINT64 = 0;
	HypercallMsr.Fields.EnableHypercallPage = 1;
	HypercallMsr.Fields.HypercallGPA = (UINT64)HvcallCodeVaVTL1 >> VSM_PAGE_SHIFT;
	__writemsr(HV_X64_MSR_HYPERCALL, HypercallMsr.AsUINT64);

}

NTSTATUS SkpPrepareForReturnToNormalMode(UINT64 rcx, UINT64 rdx)
{

	KdpDprintf(L"UefiMain!SkpPrepareForReturnToNormalMode!\n");
}


NTSTATUS HvHvRegisteGet(HV_REGISTER_NAME regname, HV_REGISTER_VALUE* regvalue)
{
	UINT8 buf[0x100];
	hvresetmemory(buf, 0x100);
	UINT64	hvcallrcx = (UINT64)buf;

	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallGetVpRegisters;
	input->CountOfElements = 1;
	//input->CallCode = HvCallInstallIntercept;
	input->IsFast = 1;
	input->Nested = 0;
	PHV_INPUT_GET_VP_REGISTERS param6 = (PHV_INPUT_GET_VP_REGISTERS)(hvcallrcx + 8);
	param6->PartitionId = HV_PARTITION_ID_SELF;
	param6->InputVtl.AsUINT8 = 0;
	param6->VpIndex = HV_VP_INDEX_SELF;

	param6->Names[0] = regname;
	UINT64	hvcallrcxsave = hvcallrcx;
	NTSTATUS ret = HVHyperCall(hvcallrcx);

	if (!NT_SUCCESS(ret))
		return ret;
	*regvalue = *(PCHV_REGISTER_VALUE)(hvcallrcxsave + HYPERCALLOUTPUTOFFSET);


	//KdpDprintf(L"UefiMain! HvHvRegisteGet %08x HVHyperCall ret:=> %08x, regvalue:=> %016llx!\n", regname, ret, regvalue->Reg64);

	return ret;

}

#define VERSION_WIN10_V5 ((5 << 16) | (0))



NTSTATUS HvHvTranslateVirtualAddress(UINT64 gva, UINT64* gpa)
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
	KdpDprintf(L"UefiMain!  HvHvTranslateVirtualAddress ret:=> %08x,res:=> %08x,gva:=> %016llx,gpa:=> %016llx!\n", ret, res.ResultCode, gva, gpapfn);

	return ret;
}


NTSTATUS HvHvCallInstallIntercept()
{
	UINT8 buf[0x100];
	hvresetmemory(buf,  0x100);
	UINT64	hvcallrcx = (UINT64)buf;
	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallInstallIntercept;
	input->IsFast = 1;
	input->Nested = 0;

	PHV_INPUT_INSTALL_INTERCEPT param = (PHV_INPUT_INSTALL_INTERCEPT)(hvcallrcx + 8);
	param->PartitionId = HV_PARTITION_ID_SELF;
	param->AccessType = HV_INTERCEPT_ACCESS_MASK_WRITE;
	param->InterceptParameter.AsUINT64 = 2;
	param->InterceptType = 0xb;


	NTSTATUS ret = HVHyperCall(hvcallrcx);

	if (!NT_SUCCESS(ret))
		return ret;

	return ret;
}


NTSTATUS HvHvCallInstallInterceptNormal()
{

	UINT64	hvcallrdx = hv_acquire_hypercall_input_page();
	UINT64	hvcallr8 = hv_acquire_hypercall_output_page();
	HV_X64_HYPERCALL_INPUT input = { 0 };
	input.AsUINT64 = 0;
	input.CallCode = HvCallInstallIntercept;
	input.IsFast = 0;
	input.Nested = 0;

	PHV_INPUT_INSTALL_INTERCEPT param = (PHV_INPUT_INSTALL_INTERCEPT)(hvcallrdx);
	param->PartitionId = HV_PARTITION_ID_SELF;
	param->AccessType = HV_INTERCEPT_ACCESS_MASK_WRITE;
	param->InterceptParameter.AsUINT64 = 2;
	param->InterceptType = 0xb;


	NTSTATUS ret = HvcallCodeVaVTL1(input.AsUINT64, hvcallrdx, hvcallr8);

	CpuSleep();

	//vtl_ret_fn(1);
	return ret;
}

NTSTATUS HvHvGetPartitionId()
{

	UINT8 buf[0x100];
	hvresetmemory(buf,  0x100);
	UINT64	hvcallrcx = (UINT64)buf;
	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallGetPartitionId;
	input->IsFast = 1;
	input->Nested = 0;

	NTSTATUS ret = HVHyperCall(hvcallrcx);

	if (!NT_SUCCESS(ret))
		return ret;

	gPartitionId = *(UINT64*)(hvcallrcx);
	KdpDprintf(L"UefiMain!  HvHvGetPartitionId HVHyperCall:=> %08x,ret:=> %016llx,gPartitionId:=> %016llx!\n", input->CallCode, ret, gPartitionId);

	return ret;
}

static void HvApicSelfIpiVtl1x2apic()
{

	int vec = 0x00;

	UINT64 icrval = APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_STARTUP | APIC_INT_ASSERT | APIC_DEST_SELF | vec;
	__writemsr(X86_MSR_IA32_X2APIC_SELF_IPI, icrval);
	__writemsr(X86_MSR_IA32_X2APIC_EOI, 0);

}

static void HVGetApicBase()
{
	MSR_IA32_APIC_BASE_REGISTER ApicBaseMsr = { 0 };
	ApicBaseMsr.Uint64 = __readmsr(X86_MSR_IA32_APIC_BASE);

	gapicpage |= ApicBaseMsr.Bits.ApicBase << VSM_PAGE_SHIFT;
	gapicpage |= ApicBaseMsr.Bits.ApicBaseHi << 32;
}
static void HVGetApicBaseVtl1()
{
	MSR_IA32_APIC_BASE_REGISTER ApicBaseMsr = { 0 };
	ApicBaseMsr.Uint64 = __readmsr(X86_MSR_IA32_APIC_BASE);

	gapicpagevtl1 |= ApicBaseMsr.Bits.ApicBase << VSM_PAGE_SHIFT;
	gapicpagevtl1 |= ApicBaseMsr.Bits.ApicBaseHi << 32;
}
static BOOLEAN is_x2apic_enabled()
{
	UINT64 apicbase = __readmsr(X86_MSR_IA32_APIC_BASE);
	BOOLEAN x2apic_enabled = (apicbase & (APIC_EN | APIC_EXTD)) == (APIC_EN | APIC_EXTD);
	if (!x2apic_enabled)
	{
		apicbase = (apicbase | (APIC_EN | APIC_EXTD));
	}
	else
	{
		return x2apic_enabled;
	}
	__writemsr(X86_MSR_IA32_APIC_BASE, apicbase);

	apicbase = __readmsr(X86_MSR_IA32_APIC_BASE);
	return (apicbase & (APIC_EN | APIC_EXTD)) == (APIC_EN | APIC_EXTD);
}



static BOOLEAN is_xapic_enabled()
{
	UINT64 apicbase = __readmsr(X86_MSR_IA32_APIC_BASE);
	BOOLEAN xapic_enabled = (apicbase & (APIC_EN)) == (APIC_EN);
	if (xapic_enabled)
	{
		HVGetApicBase();
	}
	return xapic_enabled;
}
static BOOLEAN is_xapic_enabled_vtl1()
{
	UINT64 apicbase = __readmsr(X86_MSR_IA32_APIC_BASE);
	BOOLEAN xapic_enabled = (apicbase & (APIC_EN)) == (APIC_EN);
	if (xapic_enabled)
	{
		HVGetApicBaseVtl1();
	}
	return xapic_enabled;
}


static void HvApicSelfIpiVtl0()
{

	int vec = 0x00;
	if (is_xapic_enabled())
	{
		KdpDprintf(L"UefiMain!is_xapic_enabled gapicpage:=> %016llx!\n", gapicpage);
		//UINT64 icrval = APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_STARTUP | APIC_INT_ASSERT | APIC_DEST_SELF | vec;
		//UINT32 icrvallow = 0x00044400;
		UINT32 icrvallow = 0x00044e00;
		UINT32 icrvalhi = 0x00000ffb;
		
		*(UINT32*)(gapicpage + APIC_ICR2) = icrvalhi;
		*(UINT32*)(gapicpage + APIC_ICR) = icrvallow;
		*(UINT32*)(gapicpage + APIC_EOI) = 0;
		icrvalhi = *(UINT32*)(gapicpage + APIC_ICR2);
		icrvallow = *(UINT32*)(gapicpage + APIC_ICR);
		UINT64 icrval = icrvallow;
		icrval |= icrvalhi << 32;
	//	__writemsr(HV_X64_MSR_EOM, 0);
		KdpDprintf(L"UefiMain!is_xapic_enabled icrval:=> %016llx!\n", icrval);


		//KdpDprintf(L"UefiMain!is_xapic_enabled HvMessageTypeX64SipiIntercept apic_assist_page:=> %016llx!\n", apic_assist_page);
	}
	else
	{
		KdpDprintf(L"UefiMain!is_xapic_enabled falise\n");
	}
}
static void HvApicSelfIpiVtl1()
{

	int vec = 0x00;
	if (is_xapic_enabled_vtl1())
	{

		//UINT64 icrval = APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_STARTUP | APIC_INT_ASSERT | APIC_DEST_SELF | vec;
		//UINT32 icrvallow = 0x00044400;
		/*UINT32 icrvalhi = 0x00000ffb;*/

		UINT32 icrvallow = 0x00044c00;
		UINT32 icrvalhi = 0x00000ffb;

		
		*(UINT32*)(gapicpagevtl1 + APIC_ICR2) = icrvalhi;
		*(UINT32*)(gapicpagevtl1 + APIC_ICR) = icrvallow;
		*(UINT32*)(gapicpagevtl1 + APIC_EOI) = 0;
		while (TRUE)
		{
			CpuSleep();
		}
	}

}
//不用了
NTSTATUS HvApicSelfIpiIcrVtl0()
{
	UINT8 buf[0x100];
	hvresetmemory(buf, 0x100);
	UINT64	hvcallrcx = (UINT64)buf;
	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;

	input->CallCode = HvCallSetVpRegisters;

	input->IsFast = 1;
	input->Nested = 0;
	input->CountOfElements = 1;
	PHV_INPUT_SET_VP_REGISTERS param0 = (PHV_INPUT_SET_VP_REGISTERS)(hvcallrcx + 8);
	param0->PartitionId = HV_PARTITION_ID_SELF;
	param0->InputVtl.AsUINT8 = 0;
	param0->VpIndex = HV_VP_INDEX_SELF;
	param0->Elements[0].Name = HvX64RegisterSyntheticIcr;

	UINT64* icrval = (UINT64*)
		(hvcallrcx + 0x28);
	*icrval = 0x00000ffb00044e00;


	NTSTATUS ret = HVHyperCall(hvcallrcx);
	if (!NT_SUCCESS(ret))
		return ret;
	KdpDprintf(L"UefiMain!  HvApicSelfIpiIcrVtl0 HVHyperCall:=> %08x,ret:=> %016llx!\n", input->CallCode, ret);

	return ret;
}
NTSTATUS HvHvX64RegisterCrInterceptHighMaskVtl0()
{
	UINT8 buf[0x100];
	hvresetmemory(buf, 0, 0x100);
	UINT64	hvcallrcx = (UINT64)buf;
	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;

	input->CallCode = HvCallSetVpRegisters;

	input->IsFast = 1;
	input->Nested = 0;
	input->CountOfElements = 1;
	PHV_INPUT_SET_VP_REGISTERS param0 = (PHV_INPUT_SET_VP_REGISTERS)(hvcallrcx + 8);
	param0->PartitionId = HV_PARTITION_ID_SELF;
	param0->InputVtl.AsUINT8 = 0;
	param0->VpIndex = HV_VP_INDEX_SELF;
	param0->Elements[0].Name = HvX64RegisterCrInterceptHighMask;

	UINT64* maskval = (UINT64*)
		(&param0->Elements[0].Value.Reg128);
	*maskval = 4;


	NTSTATUS ret = HVHyperCall(hvcallrcx);
	if (!NT_SUCCESS(ret))
		return ret;
	KdpDprintf(L"UefiMain!  HvHvX64RegisterCrInterceptHighMaskVtl0 HVHyperCall:=> %08x,ret:=> %016llx!\n", input->CallCode, ret);

	return ret;
}



NTSTATUS HvHvCallPostMessageVtl0(void* buffer, UINT32 buflen)
{
	
	UINT64	hvcallrdx = hv_acquire_hypercall_input_page();
	UINT64	hvcallr8 = hv_acquire_hypercall_output_page();	
	HV_X64_HYPERCALL_INPUT input = { 0 };
	input.AsUINT64 = 0;
	input.CallCode = HvCallPostMessage;
	input.IsFast = 0;
	input.Nested = 0;



	PHV_INPUT_POST_MESSAGE param1 = (PHV_INPUT_POST_MESSAGE)hvcallrdx;
	param1->ConnectionId.Id = VMBUS_MESSAGE_CONNECTION_ID_4;
	param1->MessageType = 1;
	param1->Reserved = 0;
	param1->PayloadSize = buflen;
	
	hvcopymemory(param1->Payload, buffer, buflen);

	//dumpbuf(hvcallrdx, 0x100);
	NTSTATUS ret = HvcallCodeVa(input.AsUINT64, hvcallrdx, hvcallr8);

	if (!NT_SUCCESS(ret))
		return ret;

	KdpDprintf(L"UefiMain!  HvHvCallPostMessage ret:=> %08x!\n", ret);
	
	return ret;
}

NTSTATUS HvHvCallPostMessageVtl1()
{
	

	return 0;
}




NTSTATUS HvHvRegisterVsmPartitionConfigVtl1()
{
	UINT64	hvcallrdx = hv_acquire_hypercall_input_page();
	UINT64	hvcallr8 = hv_acquire_hypercall_output_page();
	UINT64 rsppage = hv_acquire_hypercall_rsp_page();
	HV_X64_HYPERCALL_INPUT input = { 0 };
	input.CallCode = HvCallSetVpRegisters;

	input.IsFast = 0;
	input.Nested = 0;
	input.CountOfElements = 1;
	PHV_INPUT_SET_VP_REGISTERS param0 = (PHV_INPUT_SET_VP_REGISTERS)(hvcallrdx);
	param0->PartitionId = HV_PARTITION_ID_SELF;
	param0->InputVtl.AsUINT8 = 0;
	param0->VpIndex = HV_VP_INDEX_SELF;
	param0->Elements[0].Name = HvRegisterVsmPartitionConfig;

	PHV_REGISTER_VSM_PARTITION_CONFIG vsm_partition_config = (PHV_REGISTER_VSM_PARTITION_CONFIG)
		(&param0->Elements[0].Value.Reg128);
	vsm_partition_config->EnableVtlProtection = 1;
	vsm_partition_config->DefaultVtlProtectionMask = HV_PAGE_ACCESS_ALL;
	NTSTATUS ret = HvcallCodeVaVTL1(input.AsUINT64, hvcallrdx, hvcallr8);

	if (!NT_SUCCESS(ret))
		return ret;

	return ret;
}


NTSTATUS HvHvRegisterVsmVpSecureConfigVtl1()
{
	UINT64	hvcallrdx = hv_acquire_hypercall_input_page();
	UINT64	hvcallr8 = hv_acquire_hypercall_output_page();
	UINT64 rsppage = hv_acquire_hypercall_rsp_page();
	HV_X64_HYPERCALL_INPUT input = { 0 };
	input.CallCode = HvCallSetVpRegisters;

	input.IsFast = 0;
	input.Nested = 0;
	input.CountOfElements = 1;
	PHV_INPUT_SET_VP_REGISTERS param0 = (PHV_INPUT_SET_VP_REGISTERS)(hvcallrdx);
	param0->PartitionId = HV_PARTITION_ID_SELF;
	param0->InputVtl.AsUINT8 = 0;
	param0->VpIndex = HV_VP_INDEX_SELF;
	param0->Elements[0].Name = HvRegisterVsmVpSecureConfigVtl0;

	param0->Elements[0].Value.Reg64 = 1;
	NTSTATUS ret = HvcallCodeVaVTL1(input.AsUINT64, hvcallrdx, hvcallr8);

	if (!NT_SUCCESS(ret))
		return ret;

	return ret;
}


NTSTATUS HvHvModifyVtlProtectionMaskVtl1()
{
	UINT64	hvcallrdx = hv_acquire_hypercall_input_page();
	UINT64	hvcallr8 = hv_acquire_hypercall_output_page();
	UINT64 rsppage = hv_acquire_hypercall_rsp_page();
	HV_X64_HYPERCALL_INPUT input = { 0 };
	input.CallCode = HvCallModifyVtlProtectionMask;
	input.IsFast = 0;
	input.Nested = 0;
	input.CountOfElements = 1;
	PHV_MODIFY_VTL_PROTECTION_MASK param = (PHV_MODIFY_VTL_PROTECTION_MASK)(hvcallrdx);
	param->TargetPartitionId = HV_PARTITION_ID_SELF;
	param->MapFlags = HV_MAP_GPA_READABLE;
	param->TargetGpaBase[0] = VSM_PAGE_TO_PFN((UINT64)SimBaseSimpGpa);
	//param->flag = 0;
	param->InputVtl.AsUINT8 = 0;
	//NTSTATUS ret = HVHyperCall(hvcallrcx);
	NTSTATUS ret = HvcallCodeVaVTL1(input.AsUINT64, hvcallrdx, hvcallr8);

	if (!NT_SUCCESS(ret))
		return ret;

	return ret;
}




NTSTATUS HvHvModifyVtlProtectionMaskVtl0()
{
	UINT8 buf[0x100];
	hvresetmemory(buf,  0x100);
	UINT64	hvcallrcx = (UINT64)buf;
	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallModifyVtlProtectionMask;
	input->IsFast = 1;
	input->Nested = 0;
	input->CountOfElements = 1;
	PHV_MODIFY_VTL_PROTECTION_MASK param = (PHV_MODIFY_VTL_PROTECTION_MASK)(hvcallrcx + 8);
	param->TargetPartitionId = HV_PARTITION_ID_SELF;
	param->MapFlags = HV_MAP_GPA_READABLE;
	param->TargetGpaBase[0] = VSM_PAGE_TO_PFN((UINT64)SimBaseSimpGpa);
	//param->flag = 0;
	param->InputVtl.AsUINT8 = 0;
	//NTSTATUS ret = HVHyperCall(hvcallrcx);
	NTSTATUS ret = HVHyperCall(hvcallrcx);

	KdpDprintf(L"UefiMain!  HvHvModifyVtlProtectionMaskVtl0 ret:=> %08x,SimBaseSimpGpa:=> %016llx!\n", ret, SimBaseSimpGpa);

	return ret;
}



void hv_vtl_ap_entry(void)
{
	InitGlobalHvVtl1();
	HvApicSelfIpiVtl1();	
	
	
	
}


NTSTATUS HvHvCallEnablePartitionVtl()
{
	UINT8 buf[0x100];
	hvresetmemory(buf, 0x100);
	UINT64	hvcallrcx = (UINT64)buf;
	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallEnablePartitionVtl;
	input->IsFast = 1;
	input->Nested = 0;
	PHV_INPUT_SET_PARTITION_VTL param = (PHV_INPUT_SET_PARTITION_VTL)(hvcallrcx + 8);
	param->PartitionId = HV_PARTITION_ID_SELF;
	param->flag = 1;
	// param->flag = 0;
	param->InputVtl.AsUINT8 = HV_VTL_MGMT;
	//NTSTATUS ret = HVHyperCall(hvcallrcx);
	NTSTATUS ret = HVHyperCall(hvcallrcx);

	KdpDprintf(L"UefiMain!  HvCallEnablePartitionVtl HVHyperCall:=> %08x,ret:=> %016llx!\n", input->CallCode, ret);

	return ret;
}




NTSTATUS HvHvRegisterVsmPartitionConfigVtl0()
{
	UINT8 buf[0x100];
	hvresetmemory(buf,  0x100);
	UINT64	hvcallrcx = (UINT64)buf;
	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;

	input->CallCode = HvCallSetVpRegisters;

	input->IsFast = 1;
	input->Nested = 0;
	input->CountOfElements = 1;
	PHV_INPUT_SET_VP_REGISTERS param0 = (PHV_INPUT_SET_VP_REGISTERS)(hvcallrcx + 8);
	param0->PartitionId = HV_PARTITION_ID_SELF;
	param0->InputVtl.AsUINT8 = 0;
	param0->VpIndex = HV_VP_INDEX_SELF;
	param0->Elements[0].Name = HvRegisterVsmPartitionConfig;

	PHV_REGISTER_VSM_PARTITION_CONFIG vsm_partition_config = (PHV_REGISTER_VSM_PARTITION_CONFIG)
		(hvcallrcx + 0x28);
	vsm_partition_config->AsUINT64 = 0x760;
	/*vsm_partition_config->EnableVtlProtection = 1;
	vsm_partition_config->DefaultVtlProtectionMask =
		HV_PAGE_ACCESS_ALL;*/

	NTSTATUS ret = HVHyperCall(hvcallrcx);
	if (!NT_SUCCESS(ret))
		return ret;
	KdpDprintf(L"UefiMain!  HvHvRegisterVsmPartitionConfigVtl0 HVHyperCall:=> %08x,ret:=> %016llx!\n", input->CallCode, ret);

	return ret;
}

NTSTATUS HvHvCallEnableVpVtl()
{

	UINT64	hvcallrdx = hv_acquire_hypercall_input_page();
	UINT64	hvcallr8 = hv_acquire_hypercall_output_page();
	//UINT64 rsppage = hv_acquire_hypercall_rsp_page();
	HV_X64_HYPERCALL_INPUT input = { 0 };
	input.AsUINT64 = 0;
	input.CallCode = HvCallEnableVpVtl;
	input.IsFast = 0;
	input.Nested = 0;


	PHV_ENABLE_VP_VTL param1 = (PHV_ENABLE_VP_VTL)hvcallrdx;
	param1->PartitionId = HV_PARTITION_ID_SELF;
	param1->VpIndex = HV_VP_INDEX_SELF;
	param1->InputVtl.AsUINT8 = HV_VTL_MGMT;

	PHV_INITIAL_VP_CONTEXT ctx = &param1->VpVtlContext;
	ctx->Rip = hv_vtl_ap_entry;
	//ctx->Rip = HV_VTL_AP_ENTRY_HANDLER;
	//ctx->Rip = HvHvCallInstallInterceptNormal;


	HV_REGISTER_VALUE rspval = { 0 };
	HvHvRegisteGet(HvX64RegisterRsp, &rspval);


	ctx->Rsp = rspval.Reg64;
	//ctx->Rsp = rsppage;
	HV_REGISTER_VALUE Rflags = { 0 };
	HvHvRegisteGet(HvX64RegisterRflags, &Rflags);
	//ctx->Rflags = Rflags.Reg64;
	ctx->Rflags = 0x0000000000000002;

	HV_REGISTER_VALUE  Cs = { 0 };
	HvHvRegisteGet(HvX64RegisterCs, &Cs);
	Cs.Segment.Selector = 0x10;
	ctx->Cs = Cs.Segment;

	HV_REGISTER_VALUE  Ds = { 0 };
	HvHvRegisteGet(HvX64RegisterDs, &Ds);

	ctx->Ds = Ds.Segment;


	HV_REGISTER_VALUE  Es = { 0 };
	HvHvRegisteGet(HvX64RegisterEs, &Es);
	ctx->Es = Es.Segment;


	HV_REGISTER_VALUE  Fs = { 0 };
	HvHvRegisteGet(HvX64RegisterFs, &Fs);
	ctx->Fs = Fs.Segment;



	HV_REGISTER_VALUE  Gs = { 0 };
	HvHvRegisteGet(HvX64RegisterGs, &Gs);
	ctx->Gs = Gs.Segment;


	HV_REGISTER_VALUE  Ss = { 0 };
	HvHvRegisteGet(HvX64RegisterSs, &Ss);
	ctx->Ss = Ss.Segment;


	HV_REGISTER_VALUE  Tr = { 0 };
	HvHvRegisteGet(HvX64RegisterTr, &Tr);
	ctx->Tr = Tr.Segment;


	HV_REGISTER_VALUE  Ldtr = { 0 };
	HvHvRegisteGet(HvX64RegisterLdtr, &Ldtr);
	ctx->Ldtr = Ldtr.Segment;


	HV_REGISTER_VALUE  Idtr = { 0 };
	HvHvRegisteGet(HvX64RegisterIdtr, &Idtr);
	ctx->Idtr = Idtr.Table;

	HV_REGISTER_VALUE  Gdtr = { 0 };
	HvHvRegisteGet(HvX64RegisterGdtr, &Gdtr);
	ctx->Gdtr = Gdtr.Table;



	ctx->Efer = __readmsr(MSR_EFER);


	HV_REGISTER_VALUE Cr0 = { 0 };
	HvHvRegisteGet(HvX64RegisterCr0, &Cr0);
	ctx->Cr0 = Cr0.Reg64;


	HV_REGISTER_VALUE Cr3 = { 0 };
	HvHvRegisteGet(HvX64RegisterCr3, &Cr3);
	ctx->Cr3 = Cr3.Reg64;


	HV_REGISTER_VALUE Cr4 = { 0 };
	HvHvRegisteGet(HvX64RegisterCr4, &Cr4);
	ctx->Cr4 = Cr4.Reg64;
	//ctx->Cr4 = 0x110638;
	KdpDprintf(L"UefiMain!  HvCallEnableVpVtl HVHyperCall:=> %08x,Cr4:=> %016llx!\n", input.CallCode, ctx->Cr4);
	ctx->MsrCrPat = __readmsr(MSR_IA32_CR_PAT);


	NTSTATUS ret = HvcallCodeVa(input.AsUINT64, hvcallrdx, hvcallr8);

	if (!NT_SUCCESS(ret))
		return ret;
	return ret;
	//NTSTATUS ret = HVHyperCall(hvcallrcx);
	//KdpDprintf(L"UefiMain!  HvCallEnableVpVtl HVHyperCall:=> %08x,ret:=> %016llx!\n", input.CallCode, ret);
	input.AsUINT64 = 0;
	input.IsFast = 0;
	input.Nested = 0;
	input.CallCode = HvCallStartVirtualProcessor;


	ret = HvcallCodeVa(input.AsUINT64, hvcallrdx, hvcallr8);

	if (!NT_SUCCESS(ret))
		return ret;

	KdpDprintf(L"UefiMain!  HvCallStartVirtualProcessor HVHyperCall:=> %08x,ret:=> %016llx!\n", input.CallCode, ret);
	return ret;
}


NTSTATUS HvHvRegisterVsmCodePageOffsets()
{
	UINT8 buf[0x100];
	hvresetmemory(buf,  0x100);
	UINT64	hvcallrcx = (UINT64)buf;

	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallGetVpRegisters;
	input->CountOfElements = 1;
	//input->CallCode = HvCallInstallIntercept;
	input->IsFast = 1;
	input->Nested = 0;
	PHV_INPUT_GET_VP_REGISTERS param6 = (PHV_INPUT_GET_VP_REGISTERS)(hvcallrcx + 8);
	param6->PartitionId = HV_PARTITION_ID_SELF;
	param6->InputVtl.AsUINT8 = 0;
	param6->VpIndex = HV_VP_INDEX_SELF;

	param6->Names[0] = HvRegisterVsmCodePageOffsets;
	UINT64	hvcallrcxsave = hvcallrcx;
	NTSTATUS ret = HVHyperCall(hvcallrcx);

	if (!NT_SUCCESS(ret))
		return ret;
	HV_REGISTER_VALUE regvalue = *(PCHV_REGISTER_VALUE)(hvcallrcxsave + HYPERCALLOUTPUTOFFSET);

	hv_vsm_code_page_offsets vsmaddr = *(hv_vsm_code_page_offsets*)&regvalue.Reg64;
	//dumpbuf((void*)hvcallrcxsave, 0x100);
	vtl_call_fn = (TriggerCall*)(ghypercall_page + vsmaddr.u.vtl_call_offset);
	vtl_ret_fn = (TriggerCall*)(ghypercall_page + vsmaddr.u.vtl_return_offset);

	KdpDprintf(L"UefiMain! HvRegisterVsmCodePageOffsets  HVHyperCall ret:=> %08x, regvalue:=> %016llx,vtl_call_offset:=>  %08x,addr:=> %016llx,vtl_return_offset:=>  %08x,addr:=> %016llx!\n", ret, regvalue.Reg64, vsmaddr.u.vtl_call_offset, vtl_call_fn, vsmaddr.u.vtl_return_offset, vtl_ret_fn);

	return ret;
}




NTSTATUS HvHvRegisterVsmVina()
{
	UINT8 buf[0x100];
	hvresetmemory(buf, 0x100);
	UINT64	hvcallrcx = (UINT64)buf;

	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallGetVpRegisters;
	input->CountOfElements = 1;
	//input->CallCode = HvCallInstallIntercept;
	input->IsFast = 1;
	input->Nested = 0;
	PHV_INPUT_GET_VP_REGISTERS param6 = (PHV_INPUT_GET_VP_REGISTERS)(hvcallrcx + 8);
	param6->PartitionId = HV_PARTITION_ID_SELF;
	param6->InputVtl.AsUINT8 = 0;
	param6->VpIndex = HV_VP_INDEX_SELF;

	param6->Names[0] = HvRegisterVsmVina;
	UINT64	hvcallrcxsave = hvcallrcx;
	NTSTATUS ret = HVHyperCall(hvcallrcx);

	if (!NT_SUCCESS(ret))
		return ret;
	HV_REGISTER_VALUE regvalue = *(PCHV_REGISTER_VALUE)(hvcallrcxsave + HYPERCALLOUTPUTOFFSET);



	KdpDprintf(L"UefiMain! HvRegisterVsmVina  HVHyperCall ret:=> %08x, regvalue:=> %016llx!\n", ret, regvalue.Reg64);

	return ret;
}



NTSTATUS HvHvRegisterVsmVpStatus()
{
	UINT8 buf[0x100];
	hvresetmemory(buf, 0x100);
	UINT64	hvcallrcx = (UINT64)buf;

	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallGetVpRegisters;
	input->CountOfElements = 1;
	//input->CallCode = HvCallInstallIntercept;
	input->IsFast = 1;
	input->Nested = 0;
	PHV_INPUT_GET_VP_REGISTERS param6 = (PHV_INPUT_GET_VP_REGISTERS)(hvcallrcx + 8);
	param6->PartitionId = HV_PARTITION_ID_SELF;
	param6->InputVtl.AsUINT8 = 0;
	param6->VpIndex = HV_VP_INDEX_SELF;

	param6->Names[0] = HvRegisterVsmVpStatus;
	UINT64	hvcallrcxsave = hvcallrcx;
	NTSTATUS ret = HVHyperCall(hvcallrcx);

	if (!NT_SUCCESS(ret))
		return ret;
	HV_REGISTER_VALUE regvalue = *(PCHV_REGISTER_VALUE)(hvcallrcxsave + HYPERCALLOUTPUTOFFSET);



	KdpDprintf(L"UefiMain! HvRegisterVsmVpStatus  HVHyperCall ret:=> %08x, regvalue:=> %016llx!\n", ret, regvalue.Reg64);

	return ret;
}


NTSTATUS HvHvRegisterVsmPartitionStatus()
{
	UINT8 buf[0x100];
	hvresetmemory(buf, 0x100);
	UINT64	hvcallrcx = (UINT64)buf;

	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallGetVpRegisters;
	input->CountOfElements = 1;
	//input->CallCode = HvCallInstallIntercept;
	input->IsFast = 1;
	input->Nested = 0;
	PHV_INPUT_GET_VP_REGISTERS param6 = (PHV_INPUT_GET_VP_REGISTERS)(hvcallrcx + 8);
	param6->PartitionId = HV_PARTITION_ID_SELF;
	param6->InputVtl.AsUINT8 = 0;
	param6->VpIndex = HV_VP_INDEX_SELF;

	param6->Names[0] = HvRegisterVsmPartitionStatus;


	UINT64	hvcallrcxsave = hvcallrcx;
	NTSTATUS ret = HVHyperCall(hvcallrcx);
	if (!NT_SUCCESS(ret))
		return STATUS_SUCCESS;
	//dumpbuf((void*)hvcallrcxsave, 0x100);

	HV_REGISTER_VALUE regvalue = *(PCHV_REGISTER_VALUE)(hvcallrcxsave + HYPERCALLOUTPUTOFFSET);
	KdpDprintf(L"UefiMain!HvRegisterVsmPartitionStatus HVHyperCall ret:=> %08x, regvalue:=> %016llx!\n", ret, regvalue.Reg64);
	return ret;
}




NTSTATUS HvHvGetRegisterVsmPartitionConfig()
{
	UINT8 buf[0x100];
	hvresetmemory(buf, 0x100);
	UINT64	hvcallrcx = (UINT64)buf;

	PHV_X64_HYPERCALL_INPUT input = (PHV_X64_HYPERCALL_INPUT)hvcallrcx;
	input->CallCode = HvCallGetVpRegisters;
	input->CountOfElements = 1;
	//input->CallCode = HvCallInstallIntercept;
	input->IsFast = 1;
	input->Nested = 0;
	PHV_INPUT_GET_VP_REGISTERS param6 = (PHV_INPUT_GET_VP_REGISTERS)(hvcallrcx + 8);
	param6->PartitionId = HV_PARTITION_ID_SELF;
	param6->InputVtl.AsUINT8 = 0;
	param6->VpIndex = HV_VP_INDEX_SELF;

	param6->Names[0] = HvRegisterVsmPartitionConfig;


	UINT64	hvcallrcxsave = hvcallrcx;
	NTSTATUS ret = HVHyperCall(hvcallrcx);
	if (!NT_SUCCESS(ret))
		return STATUS_SUCCESS;
	//dumpbuf((void*)hvcallrcxsave, 0x100);

	HV_REGISTER_VALUE regvalue = *(PCHV_REGISTER_VALUE)(hvcallrcxsave + HYPERCALLOUTPUTOFFSET);
	KdpDprintf(L"UefiMain!HvHvGetRegisterVsmPartitionConfig HVHyperCall ret:=> %08x, regvalue:=> %016llx!\n", ret, regvalue.Reg64);
	return ret;

}
NTSTATUS hdlmsgint();


NTSTATUS patchidt(PIDT_ENTRY64 idtEntryArrtmp)
 {
	UINT64 msgsint = (UINT64)hdlmsgint;
	UINT64 hight = (UINT64)(msgsint >> 32);
	UINT64 lower_1 = (UINT64)((msgsint >> 16) & 0xffff);
	UINT64 lower_2 = (UINT64)((msgsint) & 0xffff);
	idtEntryArrtmp->hight = hight;
	UINT64 tmpmsk = 0;
	tmpmsk |= idtEntryArrtmp->u.lower & 0x0000ffffffff0000;
	tmpmsk |= lower_1 << 48;
	tmpmsk |= lower_2;
	idtEntryArrtmp->u.lower = tmpmsk;

	//KdpDprintf(L"tmpmsk=%016llx,hight=%016llx\n", idtEntryArrtmp->u.lower, idtEntryArrtmp->hight);
	return 0;
 }
NTSTATUS dumpidt() {
	NTSTATUS status = STATUS_SUCCESS;
	
	IDTR idtr = { 0 };
	PIDT_ENTRY64 idtEntryArr = NULL;
	__sidt(&idtr);
	//KdpDprintf(L"idt base:%016llx, limit:%08x\n", idtr.base, idtr.limit);
	if (idtr.base == NULL && idtr.limit <= 0) {
		return 0;
	}
	
	
	if (idtr.limit > 0x27)
	{
		PIDT_ENTRY64 idtEntryArrtmp = (PIDT_ENTRY64)((UINT64)idtr.base + (0x27*0x10));
		
		patchidt(idtEntryArrtmp);
	}

	idtEntryArr = (PIDT_ENTRY64)idtr.base;
	int i = 0;
	while (i <0x28 )
	{
		UINT64 hight = idtEntryArr->hight << 32;
		UINT64 lower_1 = (idtEntryArr->u.lower & 0xffff000000000000) >> 32;
		UINT64 lower_2 = (idtEntryArr->u.lower & 0x000000000000ffff);
		UINT64 offset = hight + lower_1 + lower_2;
		UINT16 selector = (idtEntryArr->u.lower & 0x00000000ffff0000) >> 16;	
		/*KdpDprintf(L"idx=%04x,offset=%016llx-selector=%04x-p=%04x-dpl=%04x-type=%04x-ist=%04x\n",
			i, offset, (UINT32)selector, (UINT32)idtEntryArr->u.attribute.p,
			(UINT32)idtEntryArr->u.attribute.dpl, (UINT32)idtEntryArr->u.attribute.type,
			(UINT32)idtEntryArr->u.attribute.ist);*/
		
		i++;
		idtEntryArr++;
	}
	__lidt(&idtr);
	//KdpDprintf(L"hdlmsgint=%016llx\n", hdlmsgint);
	return status;
}





EFI_STATUS
EFIAPI
UefiUnload(
	IN EFI_HANDLE ImageHandle
)
{
	// 
	// This code should be compiled out and never called 
	// 
	ASSERT(FALSE);
}

void HvConfigVtl()
{
	NTSTATUS ret = STATUS_SUCCESS;
	ret = HvHvRegisterVsmPartitionStatus();
	ret = HvHvRegisterVsmVpStatus();

	ret = HvHvCallEnablePartitionVtl();
	//ret = HvHvCallEnablePartitionVtl2();

	ret = HvHvRegisterVsmCodePageOffsets();


	ret = HvHvCallEnableVpVtl();
	//ret = HvHvCallEnableVpVtl2();

	//这个不能用
	//ret = HvHvRegisterVsmVina();
	ret = HvHvRegisterVsmPartitionStatus();


	ret = HvHvRegisterVsmVpStatus();

	ret = HvHvRegisterVsmPartitionConfigVtl0();

	//HvApicSelfIpiVtl0();
		//ret = HvHvGetRegisterVsmPartitionConfig();
	KdpDprintf(L"UefiMain!ShvlpVtlCall ret:=>  %08x!\n", ret);
	return;
}
void stall(int multi)
{
	int basecount = 100000 * multi;
	gBS->Stall(basecount);
	return;
}

VOID
EFIAPI
DisableApicTimerInterrupt(
	VOID
)
{
	LOCAL_APIC_LVT_TIMER  LvtTimer = { 0 };

	LvtTimer.Uint32 = __readmsr(X86_MSR_IA32_X2APIC_LVT_TIMER);
	LvtTimer.Bits.Mask = 1;
	__writemsr(X86_MSR_IA32_X2APIC_LVT_TIMER, LvtTimer.Uint32);
}
VOID
EFIAPI
EnableApicTimerInterrupt(
	VOID
)
{
	LOCAL_APIC_LVT_TIMER  LvtTimer={0};

	LvtTimer.Uint32 = __readmsr(X86_MSR_IA32_X2APIC_LVT_TIMER);
	LvtTimer.Bits.Mask = 0;
	__writemsr(X86_MSR_IA32_X2APIC_LVT_TIMER, LvtTimer.Uint32);
}


EFI_STATUS
EFIAPI
UefiMain(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
)
{
	EFI_STATUS efiStatus;


	SHELL_FILE_HANDLE fileHandle=NULL;
	UINT8 buffer[4];
	UINTN readSize;
	EFI_SAMPLE_DRIVER_PROTOCOL* sampleProtocol;
	NTSTATUS ret = STATUS_SUCCESS;

	efiStatus = ShellInitialize();
	if (EFI_ERROR(efiStatus))
	{
		KdpDprintf(L"Failed to initialize shell: %lx\n", efiStatus);
		goto Exit;
	}

	 _enable();
	//EnableApicTimerInterrupt();	
	 DisableApicTimerInterrupt();
	// Print stuff out 
	EnableWindbgPlugin(L"fs0:\\UefiApplication.efi");
	_enable();
	// _enable();	*/
	__debugbreak();
	fileHandle = NULL;
	ForceConsoleOutput = TRUE;
	

	PHYSICAL_ADDRESS pa_hcpage;
	hv_msr_contents hc_page;

	hc_page.as_uint64 = __readmsr(HV_X64_MSR_HYPERCALL);
	pa_hcpage = hc_page.u.guest_physical_address << PAGE_SHIFT;

	ghypercall_page = pa_hcpage;

	//dumpbuf((void*)ghypercall_page, 0x100);
	if (ForceConsoleOutput)
	{
		KdpDprintf(L"UefiMain! __readmsr HV_X64_MSR_HYPERCALL  pa_hcpage vaddr:=> %016llx,hc_page paddr:=> %016llx!\n", pa_hcpage, hc_page.as_uint64);
	}

	InitGlobalHv();


	UINT64	hvcallrdx = HvcallCodeVa;
	//HvHvTranslateVirtualAddress(hvcallrdx, NULL);
	if (ForceConsoleOutput)
	{
		dumpidt();
	}

	


	 /*stall(10);
	  _enable();
	 __debugbreak();
	 KdpDprintf(L"__fastfail(0);\r\n");
	 stall(10);
	  _enable();
	__debugbreak();
	 stall(10);
	int idx = 0;
	 while (idx<10)
	 {
		  _enable();
		
		__debugbreak();
		 stall(10);
		 idx++;
	 }
	 FindAndReportModuleImageInfoPdb(0x1000);
	 DisableApicTimerInterrupt();
	 _disable();
	 DisableWindbgPlugin();
	 goto mainentry;
	
	return efiStatus;
	*/
	
	//ret = HvHvRegisterVsmCodePageOffsets1();
	//goto Exit;
	//
	//
	// Initialize the shell library
	/*if(!hv_init_vmxe())
	{
		goto  mainentry;
	}
	if (!HvActivateVpPages())
	{
		goto  mainentry;
	}
	if (!hv_init_vp_assist_page())
	{
		goto  mainentry;
	}
	hv_run_vmxe();
	goto  mainentry;*/


	//__fastfail(0);
	//HvHvGetPartitionId();
	//HvApicSelfIpiVtl0();
     HvSYNICVtl0();
	 HvVmbusNegotiateVersion();	
	 HvVmbusRequestOffers();
	 HvVmbusOpen();
	 if (ForceConsoleOutput)
	 {
		 KdpDprintf(L"UefiMain! My handle is %lx and System Table is at %p\n",
			 ImageHandle, SystemTable);
	 }
	 _enable();
	 __debugbreak();
	 goto Exit;
	//goto  mainentry;
	//__debugbreak();
	/*
	HvSYNICVtl0();
	HvSYNICVtl1();
	HvSYNICVtl0();*/


	//HvHvX64RegisterCrInterceptHighMaskVtl0();
	//HvHvModifyVtlProtectionMaskVtl0();
	//HvHvCallPostMessage();
	//	goto  mainentry;
//	ShvlpVtlCall(0);
	KdpDprintf(L"UefiMain!HvHvRegsister ret:=>  %08x!\n", ret);

mainentry:
	

	return efiStatus;
	//
	// Open ourselves
	//
	efiStatus = ShellOpenFileByName(L"fs1:\\UefiApplication.efi",
		&fileHandle,
		EFI_FILE_MODE_READ,
		0);
	if (EFI_ERROR(efiStatus))
	{
		KdpDprintf(L"Failed to open ourselves: %lx\n", efiStatus);
		fileHandle = NULL;
		goto Exit;
	}

	//
	// Read 4 bytes at the top (MZ header)
	//
	readSize = sizeof(buffer);
	efiStatus = ShellReadFile(fileHandle, &readSize, &buffer);
	if (EFI_ERROR(efiStatus))
	{
		KdpDprintf(L"Failed to read ourselves: %lx\n", efiStatus);
		goto Exit;
	}

	//
	// Print it
	//
	KdpDprintf(L"Data: %lx\n", *(UINT32*)buffer);

	// 
	// Check if the sample driver is loaded 
	// 
	efiStatus = gBS->LocateProtocol(&gEfiSampleDriverProtocolGuid, NULL, &sampleProtocol);
	if (EFI_ERROR(efiStatus))
	{
		KdpDprintf(L"Failed to locate our driver: %lx\n", efiStatus);
		goto Exit;
	}

	// 
	// Print the value and exit 
	// 
	KdpDprintf(L"Sample driver is loaded: %lx\n", sampleProtocol->SampleValue);

Exit:
	//
	// Close our file handle
	//
	if (fileHandle != NULL)
	{
		ShellCloseFile(&fileHandle);
	}

	//
	// Sample complete!
	//
	return efiStatus;
}

