#ifndef _WINDBGKD_
#define _WINDBGKD_

//
// Dependencies
//
#include "wdbgexts.h"

//
// Conversion Macros
//
#define COPYSE(p64, p32, f)                 \
    p64->f = (ULONG64)(LONG64)(LONG)p32->f

#define KDP_MSG_BUFFER_SIZE 0x1000

//
// Default size of the Message and Path buffers
//
#define KDP_MSG_BUFFER_SIZE 0x1000

//
// Maximum supported number of breakpoints
//
#define KD_BREAKPOINT_MAX   32

#define KD_DEFAULT_LOG_BUFFER_SIZE  0x1000
//
// Dependencies
//

//
// Kernel Feature Bits
// See https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/kprcb/featurebits.htm?tx=61&ts=0,1400
//
#define KF_SMEP                         0x00000001 // Win 6.2
#define KF_RDTSC                        0x00000002 // From ks386.inc, ksamd64.inc
#define KF_CR4                          0x00000004 // From ks386.inc, ksamd64.inc
#define KF_CMOV                         0x00000008
#define KF_GLOBAL_PAGE                  0x00000010 // From ks386.inc, ksamd64.inc
#define KF_LARGE_PAGE                   0x00000020 // From ks386.inc, ksamd64.inc
#define KF_MTRR                         0x00000040
#define KF_CMPXCHG8B                    0x00000080 // From ks386.inc, ksamd64.inc
#define KF_MMX                          0x00000100
#define KF_DTS                          0x00000200 // Win 5.2-6.2
#define KF_PAT                          0x00000400
#define KF_FXSR                         0x00000800
#define KF_FAST_SYSCALL                 0x00001000 // From ks386.inc, ksamd64.inc
#define KF_XMMI                         0x00002000 // SSE
#define KF_3DNOW                        0x00004000
#define KF_AMDK6MTRR                    0x00008000 // Win 5.0-6.1
#define KF_XSAVEOPT                     0x00008000 // From KF_XSAVEOPT_BIT
#define KF_XMMI64                       0x00010000 // SSE2
#define KF_BRANCH                       0x00020000 // From ksamd64.inc, Win 6.1-6.2 
#define KF_00040000                     0x00040000 // Unclear
#define KF_SSE3                         0x00080000 // Win 6.0+
#define KF_CMPXCHG16B                   0x00100000 // Win 6.0-6.2
#define KF_AUTHENTICAMD                 0x00200000 // Win 6.1+
#define KF_ACNT2                        0x00400000 // Win 6.1+
#define KF_XSTATE                       0x00800000 // From ksamd64.inc, Win 6.1+
#define KF_GENUINE_INTEL                0x01000000 // Win 6.1+
#define KF_02000000                     0x02000000 // Unclear
#define KF_SLAT                         0x04000000 // Win 6.2+, Intel: EPT supported
#define KF_VIRT_FIRMWARE_ENABLED        0x08000000 // Win 6.2+
#define KF_RDWRFSGSBASE                 0x10000000 // From ksamd64.inc KF_RDWRFSGSBASE_BIT (0x1C)
#define KF_NX_BIT                       0x20000000
#define KF_NX_DISABLED                  0x40000000
#define KF_NX_ENABLED                   0x80000000
#define KF_RDRAND               0x0000000100000000ULL // Win 10.0+
#define KF_SMAP                 0x0000000200000000ULL // From ksamd64.inc
#define KF_RDTSCP               0x0000000400000000ULL // Win 10.0+
#define KF_HUGEPAGE             0x0000002000000000ULL // Win 10.0 1607+
#define KF_XSAVES               0x0000004000000000ULL // From ksamd64.inc KF_XSAVES_BIT (0x26)
#define KF_FPU_LEAKAGE          0x0000020000000000ULL // From ksamd64.inc KF_FPU_LEAKAGE_BIT (0x29)
#define KF_CAT                  0x0000100000000000ULL // From ksamd64.inc KF_CAT_BIT (0x02C)
#define KF_CET_SS               0x0000400000000000ULL // From ksamd64.inc
#define KF_SSSE3                0x0000800000000000ULL
#define KF_SSE4_1               0x0001000000000000ULL
#define KF_SSE4_2               0x0002000000000000ULL

#define KF_XSAVEOPT_BIT                 15 // From ksamd64.inc (0x0F -> 0x8000)
#define KF_XSTATE_BIT                   23 // From ksamd64.inc (0x17 -> 0x800000)
#define KF_RDWRFSGSBASE_BIT             28 // From ksamd64.inc (0x1C -> 0x10000000)
#define KF_XSAVES_BIT                   38 // From ksamd64.inc (0x26 -> 0x4000000000)
#define KF_FPU_LEAKAGE_BIT              41 // From ksamd64.inc (0x29 -> 0x20000000000)
#define KF_CAT_BIT                      44 // From ksamd64.inc (0x2C -> 0x100000000000)

//
// KPCR Access for non-IA64 builds
//
//#define K0IPCR                  ((ULONG_PTR)(KIP0PCRADDRESS))
//#define PCR                     ((volatile KPCR * const)K0IPCR)
#define PCR ((volatile KPCR * const)__readgsqword(FIELD_OFFSET(KPCR, Self)))
//#if defined(CONFIG_SMP) || defined(NT_BUILD)
//#undef  KeGetPcr
//#define KeGetPcr()              ((volatile KPCR * const)__readfsdword(0x1C))
//#endif

//
// Double fault stack size
//
#define DOUBLE_FAULT_STACK_SIZE 0x2000

//
// CPU Vendors
//
typedef enum
{
	CPU_UNKNOWN,
	CPU_AMD,
	CPU_INTEL,
	CPU_VIA
} CPU_VENDORS;

//
// Machine Types
//
#define MACHINE_TYPE_ISA        0x0000
#define MACHINE_TYPE_EISA       0x0001
#define MACHINE_TYPE_MCA        0x0002

//
// X86 80386 Segment Types
//
#define I386_TASK_GATE          0x5
#define I386_TSS                0x9
#define I386_ACTIVE_TSS         0xB
#define I386_CALL_GATE          0xC
#define I386_INTERRUPT_GATE     0xE
#define I386_TRAP_GATE          0xF

//
// Selector Names
//
#define RPL_MASK                0x0003
#define MODE_MASK               0x0001
#define KGDT64_NULL             0x0000
#define KGDT64_R0_CODE          0x0010
#define KGDT64_R0_DATA          0x0018
#define KGDT64_R3_CMCODE        0x0020
#define KGDT64_R3_DATA          0x0028
#define KGDT64_R3_CODE          0x0030
#define KGDT64_SYS_TSS          0x0040
#define KGDT64_R3_CMTEB         0x0050
#define KGDT64_R0_LDT           0x0060

//
// CR4
//
#define CR4_VME                 0x1
#define CR4_PVI                 0x2
#define CR4_TSD                 0x4
#define CR4_DE                  0x8
#define CR4_PSE                 0x10
#define CR4_PAE                 0x20
#define CR4_MCE                 0x40
#define CR4_PGE                 0x80
#define CR4_FXSR                0x200
#define CR4_XMMEXCPT            0x400
#define CR4_CHANNELS            0x800
#define CR4_XSAVE               0x40000

//
// DR7
//
#define DR7_LEGAL               0xFFFF0355
#define DR7_ACTIVE              0x00000355
#define DR7_TRACE_BRANCH        0x00000200
#define DR7_LAST_BRANCH         0x00000100

//
// Debug flags
//
#define DEBUG_ACTIVE_DR7                        0x0001
#define DEBUG_ACTIVE_INSTRUMENTED               0x0002
#define DEBUG_ACTIVE_DBG_INSTRUMENTED           0x0003
#define DEBUG_ACTIVE_MINIMAL_THREAD             0x0004
#define DEBUG_ACTIVE_PRIMARY_THREAD             0x0080
#define DEBUG_ACTIVE_PRIMARY_THREAD_BIT         0x0007
#define DEBUG_ACTIVE_PRIMARY_THREAD_LOCK_BIT    0x001F
#define DEBUG_ACTIVE_SCHEDULED_THREAD           0x0040
#define DEBUG_ACTIVE_SCHEDULED_THREAD_BIT       0x0006
#define DEBUG_ACTIVE_SCHEDULED_THREAD_LOCK_BIT  0x001E
#define DEBUG_ACTIVE_SCHEDULED_THREAD_LOCK      0x40000000

//
// EFlags
//
#define EFLAGS_CF               0x01L
#define EFLAGS_ZF               0x40L
#define EFLAGS_TF               0x100L
#define EFLAGS_INTERRUPT_MASK   0x200L
#define EFLAGS_DF               0x400L
#define EFLAGS_IOPL             0x3000L
#define EFLAGS_NESTED_TASK      0x4000L
//#define EFLAGS_NF               0x4000
#define EFLAGS_RF               0x10000
#define EFLAGS_V86_MASK         0x20000
#define EFLAGS_ALIGN_CHECK      0x40000
#define EFLAGS_VIF              0x80000
#define EFLAGS_VIP              0x100000
#define EFLAGS_ID               0x200000
#define EFLAGS_USER_SANITIZE    0x3F4DD7
#define EFLAG_SIGN              0x8000
#define EFLAG_ZERO              0x4000
#define EFLAGS_TF_MASK          0x0100
#define EFLAGS_TF_SHIFT         0x0008
#define EFLAGS_ID_MASK          0x200000
#define EFLAGS_IF_MASK          0x0200
#define EFLAGS_IF_SHIFT         0x0009

//
// MXCSR Floating Control/Status Bit Masks
//
#define XSW_INVALID_OPERATION   0x0001
#define XSW_DENORMAL            0x0002
#define XSW_ZERO_DIVIDE         0x0004
#define XSW_OVERFLOW            0x0008
#define XSW_UNDERFLOW           0x0010
#define XSW_PRECISION           0x0020
#define XCW_INVALID_OPERATION   0x0080
#define XCW_DENORMAL            0x0100
#define XCW_ZERO_DIVIDE         0x0200
#define XCW_OVERFLOW            0x0400
#define XCW_UNDERFLOW           0x0800
#define XCW_PRECISION           0x1000
#define XCW_ROUND_CONTROL       0x6000
#define XCW_FLUSH_ZERO          0x8000
#define XSW_ERROR_MASK          0x003F
#define XSW_ERROR_SHIFT         7

//
// Legacy floating status word bit masks.
//
#define FSW_INVALID_OPERATION   0x0001
#define FSW_DENORMAL            0x0002
#define FSW_ZERO_DIVIDE         0x0004
#define FSW_OVERFLOW            0x0008
#define FSW_UNDERFLOW           0x0010
#define FSW_PRECISION           0x0020
#define FSW_STACK_FAULT         0x0040
#define FSW_ERROR_SUMMARY       0x0080
#define FSW_CONDITION_CODE_0    0x0100
#define FSW_CONDITION_CODE_1    0x0200
#define FSW_CONDITION_CODE_2    0x0400
#define FSW_CONDITION_CODE_3    0x4000
#define FSW_ERROR_MASK          0x003F

//
// Machine Specific Registers
//
#define MSR_EFER                0xC0000080
#define MSR_STAR                0xC0000081
#define MSR_LSTAR               0xC0000082
#define MSR_CSTAR               0xC0000083
#define MSR_SYSCALL_MASK        0xC0000084
#define MSR_FS_BASE             0xC0000100
#define MSR_GS_BASE             0xC0000101
#define MSR_GS_SWAP             0xC0000102
#define MSR_MCG_STATUS          0x017A
#define MSR_AMD_ACCESS          0x9C5A203A
#define MSR_IA32_MISC_ENABLE    0x000001A0
#define MSR_LAST_BRANCH_FROM    0x01DB
#define MSR_LAST_BRANCH_TO      0x01DC
#define MSR_LAST_EXCEPTION_FROM 0x01DD
#define MSR_LAST_EXCEPTION_TO   0x01DE

//
// Caching values for the PAT MSR
//
#define PAT_UC                  0ULL
#define PAT_WC                  1ULL
#define PAT_WT                  4ULL
#define PAT_WP                  5ULL
#define PAT_WB                  6ULL
#define PAT_UCM                 7ULL

//
// Flags in MSR_EFER
//
#define MSR_SCE                 0x0001
#define MSR_LME                 0x0100
#define MSR_LMA                 0x0400
#define MSR_NXE                 0x0800
#define MSR_PAT                 0x0277
#define MSR_DEBUG_CTL           0x01D9

//
//  Flags in MSR_IA32_MISC_ENABLE
//
#define MSR_XD_ENABLE_MASK      0xFFFFFFFB

//
//  Flags in MSR_DEBUG_CTL
//
#define MSR_DEBUG_CTL_LBR       0x0001
#define MSR_DEBUG_CTL_BTF       0x0002

//
// IPI Types
//
#define IPI_APC                 1
#define IPI_DPC                 2
#define IPI_FREEZE              4
#define IPI_PACKET_READY        8
#define IPI_SYNCH_REQUEST       16

//
// PRCB Flags
//
#define PRCB_MINOR_VERSION      1
#define PRCB_MAJOR_VERSION      1
#define PRCB_BUILD_DEBUG        1
#define PRCB_BUILD_UNIPROCESSOR 2

//
// Exception active flags
//
#define KEXCEPTION_ACTIVE_INTERRUPT_FRAME 0x0000
#define KEXCEPTION_ACTIVE_EXCEPTION_FRAME 0x0001
#define KEXCEPTION_ACTIVE_SERVICE_FRAME   0x0002

//
// HAL Variables
//
#define INITIAL_STALL_COUNT     100
#define MM_HAL_VA_START         0xFFFFFFFFFFC00000ULL /* This is Vista+ */
#define MM_HAL_VA_END           0xFFFFFFFFFFFFFFFFULL
#define APIC_BASE               0xFFFFFFFFFFFE0000ULL

//
// IOPM Definitions
//
#define IO_ACCESS_MAP_NONE      0
#define IOPM_OFFSET             FIELD_OFFSET(KTSS, IoMaps[0].IoMap)
#define KiComputeIopmOffset(MapNumber)              \
    (MapNumber == IO_ACCESS_MAP_NONE) ?             \
        (USHORT)(sizeof(KTSS)) :                    \
        (USHORT)(FIELD_OFFSET(KTSS, IoMaps[MapNumber-1].IoMap))

//
// Static Kernel-Mode Address start (use MM_KSEG0_BASE for actual)
//
#define KSEG0_BASE 0xfffff80000000000ULL

#define NMI_STACK_SIZE 0x2000
#define ISR_STACK_SIZE 0x6000

//
// Synchronization-level IRQL
//
#ifndef CONFIG_SMP
#define SYNCH_LEVEL             DISPATCH_LEVEL
#else
#define SYNCH_LEVEL             (IPI_LEVEL - 2)
#endif

//
// Number of pool lookaside lists per pool in the PRCB
//
#define NUMBER_POOL_LOOKASIDE_LISTS 32


//
// Packet Size and Control Stream Size
//
#define PACKET_MAX_SIZE                     4000
#define DBGKD_MAXSTREAM                     16

//
// Magic Packet IDs
//
#define INITIAL_PACKET_ID                   0x80800000
#define SYNC_PACKET_ID                      0x00000800

//
// Magic Packet bytes
//
#define BREAKIN_PACKET                      0x62626262
#define BREAKIN_PACKET_BYTE                 0x62
#define PACKET_LEADER                       0x30303030
#define PACKET_LEADER_BYTE                  0x30
#define CONTROL_PACKET_LEADER               0x69696969
#define CONTROL_PACKET_LEADER_BYTE          0x69
#define PACKET_TRAILING_BYTE                0xAA

//
// Packet Types
//
#define PACKET_TYPE_UNUSED                  0
#define PACKET_TYPE_KD_STATE_CHANGE32       1
#define PACKET_TYPE_KD_STATE_MANIPULATE     2
#define PACKET_TYPE_KD_DEBUG_IO             3
#define PACKET_TYPE_KD_ACKNOWLEDGE          4
#define PACKET_TYPE_KD_RESEND               5
#define PACKET_TYPE_KD_RESET                6
#define PACKET_TYPE_KD_STATE_CHANGE64       7
#define PACKET_TYPE_KD_POLL_BREAKIN         8
#define PACKET_TYPE_KD_TRACE_IO             9
#define PACKET_TYPE_KD_CONTROL_REQUEST      10
#define PACKET_TYPE_KD_FILE_IO              11
#define PACKET_TYPE_MAX                     12

//
// Wait State Change Types
//
#define DbgKdMinimumStateChange             0x00003030
#define DbgKdExceptionStateChange           0x00003030
#define DbgKdLoadSymbolsStateChange         0x00003031
#define DbgKdCommandStringStateChange       0x00003032
#define DbgKdMaximumStateChange             0x00003033

//
// This is combined with the basic state change code
// if the state is from an alternate source
//
#define DbgKdAlternateStateChange           0x00010000
#define DbgKdApiMin           0x00003000
#define DbgKdApiMax           0x00003600

//
// Manipulate Types
//
#define DbgKdMinimumManipulate              0x00003130
#define DbgKdReadVirtualMemoryApi           0x00003130
#define DbgKdWriteVirtualMemoryApi          0x00003131
#define DbgKdGetContextApi                  0x00003132
#define DbgKdSetContextApi                  0x00003133
#define DbgKdWriteBreakPointApi             0x00003134
#define DbgKdRestoreBreakPointApi           0x00003135
#define DbgKdContinueApi                    0x00003136
#define DbgKdReadControlSpaceApi            0x00003137
#define DbgKdWriteControlSpaceApi           0x00003138
#define DbgKdReadIoSpaceApi                 0x00003139
#define DbgKdWriteIoSpaceApi                0x0000313A
#define DbgKdRebootApi                      0x0000313B
#define DbgKdContinueApi2                   0x0000313C
#define DbgKdReadPhysicalMemoryApi          0x0000313D
#define DbgKdWritePhysicalMemoryApi         0x0000313E
#define DbgKdQuerySpecialCallsApi           0x0000313F
#define DbgKdSetSpecialCallApi              0x00003140
#define DbgKdClearSpecialCallsApi           0x00003141
#define DbgKdSetInternalBreakPointApi       0x00003142
#define DbgKdGetInternalBreakPointApi       0x00003143
#define DbgKdReadIoSpaceExtendedApi         0x00003144
#define DbgKdWriteIoSpaceExtendedApi        0x00003145
#define DbgKdGetVersionApi                  0x00003146
#define DbgKdWriteBreakPointExApi           0x00003147
#define DbgKdRestoreBreakPointExApi         0x00003148
#define DbgKdCauseBugCheckApi               0x00003149
#define DbgKdSwitchProcessor                0x00003150
#define DbgKdPageInApi                      0x00003151
#define DbgKdReadMachineSpecificRegister    0x00003152
#define DbgKdWriteMachineSpecificRegister   0x00003153
#define OldVlm1                             0x00003154
#define OldVlm2                             0x00003155
#define DbgKdSearchMemoryApi                0x00003156
#define DbgKdGetBusDataApi                  0x00003157
#define DbgKdSetBusDataApi                  0x00003158
#define DbgKdCheckLowMemoryApi              0x00003159
#define DbgKdClearAllInternalBreakpointsApi 0x0000315A
#define DbgKdFillMemoryApi                  0x0000315B
#define DbgKdQueryMemoryApi                 0x0000315C
#define DbgKdSwitchPartition                0x0000315D
#define DbgKdWriteCustomBreakpointApi       0x0000315E
#define DbgKdGetContextExApi                0x0000315F
#define DbgKdSetContextExApi                0x00003160
#define DbgKdMaximumManipulate              0x00003161

//
// Debug I/O Types
//
#define DbgKdPrintStringApi                 0x00003230
#define DbgKdGetStringApi                   0x00003231

//
// Trace I/O Types
//
#define DbgKdPrintTraceApi                  0x00003330

//
// Control Request Types
//
#define DbgKdRequestHardwareBp              0x00004300
#define DbgKdReleaseHardwareBp              0x00004301

//
// File I/O Types
//
#define DbgKdCreateFileApi                 0x00003430
#define DbgKdReadFileApi                   0x00003431
#define DbgKdWriteFileApi                  0x00003432
#define DbgKdCloseFileApi                  0x00003433

//
// Control Report Flags
//
#define REPORT_INCLUDES_SEGS                0x0001
#define REPORT_STANDARD_CS                  0x0002

//
// Protocol Versions
//
#define DBGKD_64BIT_PROTOCOL_VERSION1       5
#define DBGKD_64BIT_PROTOCOL_VERSION2       6

//
// Query Memory Address Spaces
//
#define DBGKD_QUERY_MEMORY_VIRTUAL          0
#define DBGKD_QUERY_MEMORY_PROCESS          0
#define DBGKD_QUERY_MEMORY_SESSION          1
#define DBGKD_QUERY_MEMORY_KERNEL           2

//
// Query Memory Flags
//
#define DBGKD_QUERY_MEMORY_READ             0x01
#define DBGKD_QUERY_MEMORY_WRITE            0x02
#define DBGKD_QUERY_MEMORY_EXECUTE          0x04
#define DBGKD_QUERY_MEMORY_FIXED            0x08

//
// Internal Breakpoint Flags
//
#define DBGKD_INTERNAL_BP_FLAG_COUNTONLY    0x01
#define DBGKD_INTERNAL_BP_FLAG_INVALID      0x02
#define DBGKD_INTERNAL_BP_FLAG_SUSPENDED    0x04
#define DBGKD_INTERNAL_BP_FLAG_DYING        0x08

//
// Fill Memory Flags
//
#define DBGKD_FILL_MEMORY_VIRTUAL           0x01
#define DBGKD_FILL_MEMORY_PHYSICAL          0x02

//
// Physical Memory Caching Flags
//
#define DBGKD_CACHING_DEFAULT               0
#define DBGKD_CACHING_CACHED                1
#define DBGKD_CACHING_UNCACHED              2
#define DBGKD_CACHING_WRITE_COMBINED        3

//
// Partition Switch Flags
//
#define DBGKD_PARTITION_DEFAULT             0x00
#define DBGKD_PARTITION_ALTERNATE           0x01

//
// AMD64 Control Space types
//
#define AMD64_DEBUG_CONTROL_SPACE_KPCR 0
#define AMD64_DEBUG_CONTROL_SPACE_KPRCB 1
#define AMD64_DEBUG_CONTROL_SPACE_KSPECIAL 2
#define AMD64_DEBUG_CONTROL_SPACE_KTHREAD 3

#define EXCEPTION_MAXIMUM_PARAMETERS 15

typedef enum _INTERFACE_TYPE {
	InterfaceTypeUndefined = -1,
	Internal,
	Isa,
	Eisa,
	MicroChannel,
	TurboChannel,
	PCIBus,
	VMEBus,
	NuBus,
	PCMCIABus,
	CBus,
	MPIBus,
	MPSABus,
	ProcessorInternal,
	InternalPowerBus,
	PNPISABus,
	PNPBus,
	Vmcs,
	MaximumInterfaceType
} INTERFACE_TYPE, * PINTERFACE_TYPE;


typedef struct DECLSPEC_ALIGN(16) _XSAVE_FORMAT {
    USHORT ControlWord;
    USHORT StatusWord;
    UCHAR TagWord;
    UCHAR Reserved1;
    USHORT ErrorOpcode;
    ULONG ErrorOffset;
    USHORT ErrorSelector;
    USHORT Reserved2;
    ULONG DataOffset;
    USHORT DataSelector;
    USHORT Reserved3;
    ULONG MxCsr;
    ULONG MxCsr_Mask;
    M128A FloatRegisters[8];

    M128A XmmRegisters[16];
    UCHAR Reserved4[96];

} XSAVE_FORMAT, * PXSAVE_FORMAT;


typedef struct _KFLOATING_SAVE
{
	ULONG Dummy;
} KFLOATING_SAVE, * PKFLOATING_SAVE;

typedef XSAVE_FORMAT XMM_SAVE_AREA32, * PXMM_SAVE_AREA32;

typedef struct DECLSPEC_ALIGN(16) _CONTEXT {
	ULONG64 P1Home;
	ULONG64 P2Home;
	ULONG64 P3Home;
	ULONG64 P4Home;
	ULONG64 P5Home;
	ULONG64 P6Home;
	ULONG ContextFlags;
	ULONG MxCsr;
	USHORT SegCs;
	USHORT SegDs;
	USHORT SegEs;
	USHORT SegFs;
	USHORT SegGs;
	USHORT SegSs;
	ULONG EFlags;
	ULONG64 Dr0;
	ULONG64 Dr1;
	ULONG64 Dr2;
	ULONG64 Dr3;
	ULONG64 Dr6;
	ULONG64 Dr7;
	ULONG64 Rax;
	ULONG64 Rcx;
	ULONG64 Rdx;
	ULONG64 Rbx;
	ULONG64 Rsp;
	ULONG64 Rbp;
	ULONG64 Rsi;
	ULONG64 Rdi;
	ULONG64 R8;
	ULONG64 R9;
	ULONG64 R10;
	ULONG64 R11;
	ULONG64 R12;
	ULONG64 R13;
	ULONG64 R14;
	ULONG64 R15;
	ULONG64 Rip;
	union {
		XMM_SAVE_AREA32 FltSave;
		struct {
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		} xmm;
	} u;
	M128A VectorRegister[26];
	ULONG64 VectorControl;
	ULONG64 DebugControl;
	ULONG64 LastBranchToRip;
	ULONG64 LastBranchFromRip;
	ULONG64 LastExceptionToRip;
	ULONG64 LastExceptionFromRip;
} CONTEXT,* PCONTEXT;

typedef struct _KDESCRIPTOR
{
	USHORT Pad[3];
	USHORT Limit;
	PVOID Base;
} KDESCRIPTOR, * PKDESCRIPTOR;



typedef struct _KSPECIAL_REGISTERS
{
	ULONG64 Cr0;
	ULONG64 Cr2;
	ULONG64 Cr3;
	ULONG64 Cr4;
	ULONG64 KernelDr0;
	ULONG64 KernelDr1;
	ULONG64 KernelDr2;
	ULONG64 KernelDr3;
	ULONG64 KernelDr6;
	ULONG64 KernelDr7;
	KDESCRIPTOR Gdtr;
	KDESCRIPTOR Idtr;
	USHORT Tr;
	USHORT Ldtr;
	ULONG MxCsr;
	ULONG64 DebugControl;
	ULONG64 LastBranchToRip;
	ULONG64 LastBranchFromRip;
	ULONG64 LastExceptionToRip;
	ULONG64 LastExceptionFromRip;
	ULONG64 Cr8;
	ULONG64 MsrGsBase;
	ULONG64 MsrGsSwap;
	ULONG64 MsrStar;
	ULONG64 MsrLStar;
	ULONG64 MsrCStar;
	ULONG64 MsrSyscallMask;
} KSPECIAL_REGISTERS, * PKSPECIAL_REGISTERS;


typedef struct _KD_X64_SEGMENT_REGISTER
{
	UINT64 Base;
	UINT32 Limit;
	UINT16 Selector;
	union
	{
		struct
		{
			UINT16 SegmentType : 4;
			UINT16 NonSystemSegment : 1;
			UINT16 DescriptorPrivilegeLevel : 2;
			UINT16 Present : 1;
			UINT16 Reserved : 4;
			UINT16 Available : 1;
			UINT16 Long : 1;
			UINT16 Default : 1;
			UINT16 Granularity : 1;
		}u1;
		UINT16 Attributes;
	}u;

} KD_X64_SEGMENT_REGISTER, * PKD_X64_SEGMENT_REGISTER;

/* Exception records */
typedef struct _EXCEPTION_RECORD {
	NTSTATUS ExceptionCode;
	ULONG ExceptionFlags;
	struct _EXCEPTION_RECORD* ExceptionRecord;
	PVOID ExceptionAddress;
	ULONG NumberParameters;
	ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, * PEXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD32 {
	NTSTATUS ExceptionCode;
	ULONG ExceptionFlags;
	ULONG ExceptionRecord;
	ULONG ExceptionAddress;
	ULONG NumberParameters;
	ULONG ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD32, * PEXCEPTION_RECORD32;

typedef struct _EXCEPTION_RECORD64 {
	NTSTATUS ExceptionCode;
	ULONG ExceptionFlags;
	ULONG64 ExceptionRecord;
	ULONG64 ExceptionAddress;
	ULONG NumberParameters;
	ULONG __unusedAlignment;
	ULONG64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD64, * PEXCEPTION_RECORD64;

typedef struct _EXCEPTION_POINTERS {
	PEXCEPTION_RECORD ExceptionRecord;
	PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, * PEXCEPTION_POINTERS;

// KD Packet Structure
//
typedef struct _KD_PACKET
{
    ULONG PacketLeader;
    USHORT PacketType;
    USHORT ByteCount;
    ULONG PacketId;
    ULONG Checksum;   
} KD_PACKET, *PKD_PACKET;


typedef struct _KD_PACKETEXTRA
{
    LIST_ENTRY_UEFI List;
    KD_PACKET  Packet;
	STRING MessageHeader;
	STRING MessageData;
} KD_PACKETEXTRA, * PKD_PACKETEXTRA;

//
// KD Context
//
typedef struct _KD_CONTEXT
{
    ULONG KdpDefaultRetries;
    BOOLEAN KdpControlCPending;    
    BOOLEAN KdpControlReturn;    
} KD_CONTEXT, *PKD_CONTEXT;

//
// Control Sets for Supported Architectures
//
#include <pshpack4.h>
typedef struct _X86_DBGKD_CONTROL_SET
{
    ULONG TraceFlag;
    ULONG Dr7;
    ULONG CurrentSymbolStart;
    ULONG CurrentSymbolEnd;
} X86_DBGKD_CONTROL_SET, *PX86_DBGKD_CONTROL_SET;

typedef struct _ALPHA_DBGKD_CONTROL_SET
{
    ULONG __padding;
} ALPHA_DBGKD_CONTROL_SET, *PALPHA_DBGKD_CONTROL_SET;

typedef struct _IA64_DBGKD_CONTROL_SET
{
    ULONG Continue;
    ULONG64 CurrentSymbolStart;
    ULONG64 CurrentSymbolEnd;
} IA64_DBGKD_CONTROL_SET, *PIA64_DBGKD_CONTROL_SET;

typedef struct _AMD64_DBGKD_CONTROL_SET
{
    ULONG TraceFlag;
    ULONG64 Dr7;
    ULONG64 CurrentSymbolStart;
    ULONG64 CurrentSymbolEnd;
} AMD64_DBGKD_CONTROL_SET, *PAMD64_DBGKD_CONTROL_SET;

typedef struct _ARM_DBGKD_CONTROL_SET
{
    ULONG Continue;
    ULONG CurrentSymbolStart;
    ULONG CurrentSymbolEnd;
} ARM_DBGKD_CONTROL_SET, *PARM_DBGKD_CONTROL_SET;

typedef struct _ARM64_DBGKD_CONTROL_SET
{
    ULONG Continue;
    ULONG CurrentSymbolStart;
    ULONG CurrentSymbolEnd;
} ARM64_DBGKD_CONTROL_SET, *PARM64_DBGKD_CONTROL_SET;

typedef struct _DBGKD_ANY_CONTROL_SET
{
    union
    {
        X86_DBGKD_CONTROL_SET X86ControlSet;
        ALPHA_DBGKD_CONTROL_SET AlphaControlSet;
        IA64_DBGKD_CONTROL_SET IA64ControlSet;
        AMD64_DBGKD_CONTROL_SET Amd64ControlSet;
        ARM_DBGKD_CONTROL_SET ARMControlSet;
    }u;
} DBGKD_ANY_CONTROL_SET, *PDBGKD_ANY_CONTROL_SET;
#include <poppack.h>

#if defined(_M_IX86)
typedef X86_DBGKD_CONTROL_SET DBGKD_CONTROL_SET, *PDBGKD_CONTROL_SET;
#elif defined(_M_AMD64)
typedef AMD64_DBGKD_CONTROL_SET DBGKD_CONTROL_SET, *PDBGKD_CONTROL_SET;
#elif defined(_M_ARM)
typedef ARM_DBGKD_CONTROL_SET DBGKD_CONTROL_SET, *PDBGKD_CONTROL_SET;
#elif defined(_M_ARM64)
typedef ARM64_DBGKD_CONTROL_SET DBGKD_CONTROL_SET, *PDBGKD_CONTROL_SET;
#else
#error Unsupported Architecture
#endif

//
// DBGKM Structure for Exceptions
//
typedef struct _DBGKM_EXCEPTION32
{
    EXCEPTION_RECORD32 ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION32, *PDBGKM_EXCEPTION32;

typedef struct _DBGKM_EXCEPTION64
{
    EXCEPTION_RECORD64 ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION64, *PDBGKM_EXCEPTION64;

//
// DBGKD Structure for State Change
//
typedef struct _X86_DBGKD_CONTROL_REPORT
{
    ULONG   Dr6;
    ULONG   Dr7;
    USHORT  InstructionCount;
    USHORT  ReportFlags;
    UCHAR   InstructionStream[DBGKD_MAXSTREAM];
    USHORT  SegCs;
    USHORT  SegDs;
    USHORT  SegEs;
    USHORT  SegFs;
    ULONG   EFlags;
} X86_DBGKD_CONTROL_REPORT, *PX86_DBGKD_CONTROL_REPORT;

typedef struct _ALPHA_DBGKD_CONTROL_REPORT
{
    ULONG InstructionCount;
    UCHAR InstructionStream[DBGKD_MAXSTREAM];
} ALPHA_DBGKD_CONTROL_REPORT, *PALPHA_DBGKD_CONTROL_REPORT;

typedef struct _IA64_DBGKD_CONTROL_REPORT
{
    ULONG InstructionCount;
    UCHAR InstructionStream[DBGKD_MAXSTREAM];
} IA64_DBGKD_CONTROL_REPORT, *PIA64_DBGKD_CONTROL_REPORT;

typedef struct _AMD64_DBGKD_CONTROL_REPORT
{
    ULONG64 Dr6;
    ULONG64 Dr7;
    ULONG EFlags;
    USHORT InstructionCount;
    USHORT ReportFlags;
    UCHAR InstructionStream[DBGKD_MAXSTREAM];
    USHORT SegCs;
    USHORT SegDs;
    USHORT SegEs;
    USHORT SegFs;
} AMD64_DBGKD_CONTROL_REPORT, *PAMD64_DBGKD_CONTROL_REPORT;

typedef struct _ARM_DBGKD_CONTROL_REPORT
{
    ULONG Cpsr;
    ULONG InstructionCount;
    UCHAR InstructionStream[DBGKD_MAXSTREAM];
} ARM_DBGKD_CONTROL_REPORT, *PARM_DBGKD_CONTROL_REPORT;

typedef struct _ARM64_DBGKD_CONTROL_REPORT
{
    ULONG64 Bvr;
    ULONG64 Wvr;
    ULONG InstructionCount;
    UCHAR InstructionStream[DBGKD_MAXSTREAM];
} ARM64_DBGKD_CONTROL_REPORT, *PARM64_DBGKD_CONTROL_REPORT;

typedef struct _DBGKD_ANY_CONTROL_REPORT
{
    union
    {
        X86_DBGKD_CONTROL_REPORT X86ControlReport;
        ALPHA_DBGKD_CONTROL_REPORT AlphaControlReport;
        IA64_DBGKD_CONTROL_REPORT IA64ControlReport;
        AMD64_DBGKD_CONTROL_REPORT Amd64ControlReport;
        ARM_DBGKD_CONTROL_REPORT ARMControlReport;
        ARM64_DBGKD_CONTROL_REPORT ARM64ControlReport;
    }u;
} DBGKD_ANY_CONTROL_REPORT, *PDBGKD_ANY_CONTROL_REPORT;

#if defined(_M_IX86)
typedef X86_DBGKD_CONTROL_REPORT DBGKD_CONTROL_REPORT, *PDBGKD_CONTROL_REPORT;
#elif defined(_M_AMD64)
typedef AMD64_DBGKD_CONTROL_REPORT DBGKD_CONTROL_REPORT, *PDBGKD_CONTROL_REPORT;
#elif defined(_M_ARM)
typedef ARM_DBGKD_CONTROL_REPORT DBGKD_CONTROL_REPORT, *PDBGKD_CONTROL_REPORT;
#elif defined(_M_ARM64)
typedef ARM64_DBGKD_CONTROL_REPORT DBGKD_CONTROL_REPORT, *PDBGKD_CONTROL_REPORT;
#else
#error Unsupported Architecture
#endif

//
// DBGKD Structure for Debug I/O Type Print String
//
typedef struct _DBGKD_PRINT_STRING
{
    ULONG LengthOfString;
} DBGKD_PRINT_STRING, *PDBGKD_PRINT_STRING;

//
// DBGKD Structure for Debug I/O Type Get String
//
typedef struct _DBGKD_GET_STRING
{
    ULONG LengthOfPromptString;
    ULONG LengthOfStringRead;
} DBGKD_GET_STRING, *PDBGKD_GET_STRING;

//
// DBGKD Structure for Debug I/O
//
typedef struct _DBGKD_DEBUG_IO
{
    ULONG ApiNumber;
    USHORT ProcessorLevel;
    USHORT Processor;
    union
    {
        DBGKD_PRINT_STRING PrintString;
        DBGKD_GET_STRING GetString;
    } u;
} DBGKD_DEBUG_IO, *PDBGKD_DEBUG_IO;

//
// DBGkD Structure for Command String
//
typedef struct _DBGKD_COMMAND_STRING
{
    ULONG Flags;
    ULONG Reserved1;
    ULONG64 Reserved2[7];
} DBGKD_COMMAND_STRING, *PDBGKD_COMMAND_STRING;

//
// DBGKD Structure for Load Symbols
//
typedef struct _DBGKD_LOAD_SYMBOLS32
{
    ULONG PathNameLength;
    ULONG BaseOfDll;
    ULONG ProcessId;
    ULONG CheckSum;
    ULONG SizeOfImage;
    BOOLEAN UnloadSymbols;
} DBGKD_LOAD_SYMBOLS32, *PDBGKD_LOAD_SYMBOLS32;

typedef struct _DBGKD_LOAD_SYMBOLS64
{
    ULONG PathNameLength;
    ULONG64 BaseOfDll;
    ULONG64 ProcessId;
    ULONG CheckSum;
    ULONG SizeOfImage;
    BOOLEAN UnloadSymbols;
} DBGKD_LOAD_SYMBOLS64, *PDBGKD_LOAD_SYMBOLS64;

//
// DBGKD Structure for Wait State Change
//

typedef struct _DBGKD_WAIT_STATE_CHANGE32
{
    ULONG NewState;
    USHORT ProcessorLevel;
    USHORT Processor;
    ULONG NumberProcessors;
    ULONG Thread;
    ULONG ProgramCounter;
    union
    {
        DBGKM_EXCEPTION32 Exception;
        DBGKD_LOAD_SYMBOLS32 LoadSymbols;
    } u;
} DBGKD_WAIT_STATE_CHANGE32, *PDBGKD_WAIT_STATE_CHANGE32;

typedef struct _DBGKD_WAIT_STATE_CHANGE64
{
    ULONG NewState;
    USHORT ProcessorLevel;
    USHORT Processor;
    ULONG NumberProcessors;
    ULONG64 Thread;
    ULONG64 ProgramCounter;
    union
    {
        DBGKM_EXCEPTION64 Exception;
        DBGKD_LOAD_SYMBOLS64 LoadSymbols;
    } u;
} DBGKD_WAIT_STATE_CHANGE64, *PDBGKD_WAIT_STATE_CHANGE64;

typedef struct _DBGKD_ANY_WAIT_STATE_CHANGE
{
    ULONG NewState;
    USHORT ProcessorLevel;
    USHORT Processor;
    ULONG NumberProcessors;
    ULONG64 Thread;
    ULONG64 ProgramCounter;
    union
    {
        DBGKM_EXCEPTION64 Exception;
        DBGKD_LOAD_SYMBOLS64 LoadSymbols;
        DBGKD_COMMAND_STRING CommandString;
    } u;
    union
    {
        DBGKD_CONTROL_REPORT ControlReport;
        DBGKD_ANY_CONTROL_REPORT AnyControlReport;
    }u1;
} DBGKD_ANY_WAIT_STATE_CHANGE, *PDBGKD_ANY_WAIT_STATE_CHANGE;

//
// DBGKD Manipulate Structures
//
typedef struct _DBGKD_READ_MEMORY32
{
    ULONG TargetBaseAddress;
    ULONG TransferCount;
    ULONG ActualBytesRead;
} DBGKD_READ_MEMORY32, *PDBGKD_READ_MEMORY32;

typedef struct _DBGKD_READ_MEMORY64
{
    ULONG64 TargetBaseAddress;
    ULONG TransferCount;
    ULONG ActualBytesRead;
} DBGKD_READ_MEMORY64, *PDBGKD_READ_MEMORY64;

typedef struct _DBGKD_WRITE_MEMORY32
{
    ULONG TargetBaseAddress;
    ULONG TransferCount;
    ULONG ActualBytesWritten;
} DBGKD_WRITE_MEMORY32, *PDBGKD_WRITE_MEMORY32;

typedef struct _DBGKD_WRITE_MEMORY64
{
    ULONG64 TargetBaseAddress;
    ULONG TransferCount;
    ULONG ActualBytesWritten;
} DBGKD_WRITE_MEMORY64, *PDBGKD_WRITE_MEMORY64;

typedef struct _DBGKD_GET_CONTEXT
{
    ULONG Unused;
} DBGKD_GET_CONTEXT, *PDBGKD_GET_CONTEXT;

typedef struct _DBGKD_SET_CONTEXT
{
    ULONG ContextFlags;
} DBGKD_SET_CONTEXT, *PDBGKD_SET_CONTEXT;

typedef struct _DBGKD_WRITE_BREAKPOINT32
{
    ULONG BreakPointAddress;
    ULONG BreakPointHandle;
} DBGKD_WRITE_BREAKPOINT32, *PDBGKD_WRITE_BREAKPOINT32;

typedef struct _DBGKD_WRITE_BREAKPOINT64
{
    ULONG64 BreakPointAddress;
    ULONG BreakPointHandle;
} DBGKD_WRITE_BREAKPOINT64, *PDBGKD_WRITE_BREAKPOINT64;

typedef struct _DBGKD_RESTORE_BREAKPOINT
{
    ULONG BreakPointHandle;
} DBGKD_RESTORE_BREAKPOINT, *PDBGKD_RESTORE_BREAKPOINT;

typedef struct _DBGKD_CONTINUE
{
    NTSTATUS ContinueStatus;
} DBGKD_CONTINUE, *PDBGKD_CONTINUE;

#include <pshpack4.h>
typedef struct _DBGKD_CONTINUE2
{
    NTSTATUS ContinueStatus;
    union
    {
        DBGKD_CONTROL_SET ControlSet;
        DBGKD_ANY_CONTROL_SET AnyControlSet;
    }u;
} DBGKD_CONTINUE2, *PDBGKD_CONTINUE2;
#include <poppack.h>

typedef struct _DBGKD_READ_WRITE_IO32
{
    ULONG IoAddress;
    ULONG DataSize;
    ULONG DataValue;
} DBGKD_READ_WRITE_IO32, *PDBGKD_READ_WRITE_IO32;

typedef struct _DBGKD_READ_WRITE_IO64
{
    ULONG64 IoAddress;
    ULONG DataSize;
    ULONG DataValue;
} DBGKD_READ_WRITE_IO64, *PDBGKD_READ_WRITE_IO64;

typedef struct _DBGKD_READ_WRITE_IO_EXTENDED32
{
    ULONG DataSize;
    ULONG InterfaceType;
    ULONG BusNumber;
    ULONG AddressSpace;
    ULONG IoAddress;
    ULONG DataValue;
} DBGKD_READ_WRITE_IO_EXTENDED32, *PDBGKD_READ_WRITE_IO_EXTENDED32;

typedef struct _DBGKD_READ_WRITE_IO_EXTENDED64
{
    ULONG DataSize;
    ULONG InterfaceType;
    ULONG BusNumber;
    ULONG AddressSpace;
    ULONG64 IoAddress;
    ULONG DataValue;
} DBGKD_READ_WRITE_IO_EXTENDED64, *PDBGKD_READ_WRITE_IO_EXTENDED64;

typedef struct _DBGKD_READ_WRITE_MSR
{
    ULONG Msr;
    ULONG DataValueLow;
    ULONG DataValueHigh;
} DBGKD_READ_WRITE_MSR, *PDBGKD_READ_WRITE_MSR;

typedef struct _DBGKD_QUERY_SPECIAL_CALLS
{
    ULONG NumberOfSpecialCalls;
} DBGKD_QUERY_SPECIAL_CALLS, *PDBGKD_QUERY_SPECIAL_CALLS;

typedef struct _DBGKD_SET_SPECIAL_CALL32
{
    ULONG SpecialCall;
} DBGKD_SET_SPECIAL_CALL32, *PDBGKD_SET_SPECIAL_CALL32;

typedef struct _DBGKD_SET_SPECIAL_CALL64
{
    ULONG64 SpecialCall;
} DBGKD_SET_SPECIAL_CALL64, *PDBGKD_SET_SPECIAL_CALL64;

typedef struct _DBGKD_SET_INTERNAL_BREAKPOINT32
{
    ULONG BreakpointAddress;
    ULONG Flags;
} DBGKD_SET_INTERNAL_BREAKPOINT32, *PDBGKD_SET_INTERNAL_BREAKPOINT32;

typedef struct _DBGKD_SET_INTERNAL_BREAKPOINT64
{
    ULONG64 BreakpointAddress;
    ULONG Flags;
} DBGKD_SET_INTERNAL_BREAKPOINT64, *PDBGKD_SET_INTERNAL_BREAKPOINT64;

typedef struct _DBGKD_GET_INTERNAL_BREAKPOINT32
{
    ULONG BreakpointAddress;
    ULONG Flags;
    ULONG Calls;
    ULONG MaxCallsPerPeriod;
    ULONG MinInstructions;
    ULONG MaxInstructions;
    ULONG TotalInstructions;
} DBGKD_GET_INTERNAL_BREAKPOINT32, *PDBGKD_GET_INTERNAL_BREAKPOINT32;

typedef struct _DBGKD_GET_INTERNAL_BREAKPOINT64
{
    ULONG64 BreakpointAddress;
    ULONG Flags;
    ULONG Calls;
    ULONG MaxCallsPerPeriod;
    ULONG MinInstructions;
    ULONG MaxInstructions;
    ULONG TotalInstructions;
} DBGKD_GET_INTERNAL_BREAKPOINT64, *PDBGKD_GET_INTERNAL_BREAKPOINT64;

typedef struct _DBGKD_BREAKPOINTEX
{
    ULONG BreakPointCount;
    NTSTATUS ContinueStatus;
} DBGKD_BREAKPOINTEX, *PDBGKD_BREAKPOINTEX;

typedef struct _DBGKD_SEARCH_MEMORY
{
    union
    {
        ULONG64 SearchAddress;
        ULONG64 FoundAddress;
    }u;
    ULONG64 SearchLength;
    ULONG PatternLength;
} DBGKD_SEARCH_MEMORY, *PDBGKD_SEARCH_MEMORY;

typedef struct _DBGKD_GET_SET_BUS_DATA
{
    ULONG BusDataType;
    ULONG BusNumber;
    ULONG SlotNumber;
    ULONG Offset;
    ULONG Length;
} DBGKD_GET_SET_BUS_DATA, *PDBGKD_GET_SET_BUS_DATA;

typedef struct _DBGKD_FILL_MEMORY
{
    ULONG64 Address;
    ULONG Length;
    USHORT Flags;
    USHORT PatternLength;
} DBGKD_FILL_MEMORY, *PDBGKD_FILL_MEMORY;

typedef struct _DBGKD_QUERY_MEMORY
{
    ULONG64 Address;
    ULONG64 Reserved;
    ULONG AddressSpace;
    ULONG Flags;
} DBGKD_QUERY_MEMORY, *PDBGKD_QUERY_MEMORY;

typedef struct _DBGKD_SWITCH_PARTITION
{
    ULONG Partition;
} DBGKD_SWITCH_PARTITION;

typedef struct _DBGKD_CONTEXT_EX
{
   ULONG Offset;
   ULONG ByteCount;
   ULONG BytesCopied;
} DBGKD_CONTEXT_EX, *PDBGKD_CONTEXT_EX;

typedef struct _DBGKD_WRITE_CUSTOM_BREAKPOINT
{
   ULONG64 BreakPointAddress;
   ULONG64 BreakPointInstruction;
   ULONG BreakPointHandle;
   UCHAR BreakPointInstructionSize;
   UCHAR BreakPointInstructionAlignment;
} DBGKD_WRITE_CUSTOM_BREAKPOINT, *PDBGKD_WRITE_CUSTOM_BREAKPOINT;

//
// DBGKD Structure for Manipulate
//
typedef struct _DBGKD_MANIPULATE_STATE32
{
    ULONG ApiNumber;
    USHORT ProcessorLevel;
    USHORT Processor;
    NTSTATUS ReturnStatus;
    union
    {
        DBGKD_READ_MEMORY32 ReadMemory;
        DBGKD_WRITE_MEMORY32 WriteMemory;
        DBGKD_READ_MEMORY64 ReadMemory64;
        DBGKD_WRITE_MEMORY64 WriteMemory64;
        DBGKD_GET_CONTEXT GetContext;
        DBGKD_SET_CONTEXT SetContext;
        DBGKD_WRITE_BREAKPOINT32 WriteBreakPoint;
        DBGKD_RESTORE_BREAKPOINT RestoreBreakPoint;
        DBGKD_CONTINUE Continue;
        DBGKD_CONTINUE2 Continue2;
        DBGKD_READ_WRITE_IO32 ReadWriteIo;
        DBGKD_READ_WRITE_IO_EXTENDED32 ReadWriteIoExtended;
        DBGKD_QUERY_SPECIAL_CALLS QuerySpecialCalls;
        DBGKD_SET_SPECIAL_CALL32 SetSpecialCall;
        DBGKD_SET_INTERNAL_BREAKPOINT32 SetInternalBreakpoint;
        DBGKD_GET_INTERNAL_BREAKPOINT32 GetInternalBreakpoint;
        DBGKD_GET_VERSION32 GetVersion32;
        DBGKD_BREAKPOINTEX BreakPointEx;
        DBGKD_READ_WRITE_MSR ReadWriteMsr;
        DBGKD_SEARCH_MEMORY SearchMemory;
        DBGKD_GET_SET_BUS_DATA GetSetBusData;
        DBGKD_FILL_MEMORY FillMemory;
        DBGKD_QUERY_MEMORY QueryMemory;
        DBGKD_SWITCH_PARTITION SwitchPartition;
    } u;
} DBGKD_MANIPULATE_STATE32, *PDBGKD_MANIPULATE_STATE32;

typedef struct _DBGKD_MANIPULATE_STATE64
{
    ULONG ApiNumber;
    USHORT ProcessorLevel;
    USHORT Processor;
    NTSTATUS ReturnStatus;
    union
    {
        DBGKD_READ_MEMORY64 ReadMemory;
        DBGKD_WRITE_MEMORY64 WriteMemory;
        DBGKD_GET_CONTEXT GetContext;
        DBGKD_SET_CONTEXT SetContext;
        DBGKD_WRITE_BREAKPOINT64 WriteBreakPoint;
        DBGKD_RESTORE_BREAKPOINT RestoreBreakPoint;
        DBGKD_CONTINUE Continue;
        DBGKD_CONTINUE2 Continue2;
        DBGKD_READ_WRITE_IO64 ReadWriteIo;
        DBGKD_READ_WRITE_IO_EXTENDED64 ReadWriteIoExtended;
        DBGKD_QUERY_SPECIAL_CALLS QuerySpecialCalls;
        DBGKD_SET_SPECIAL_CALL64 SetSpecialCall;
        DBGKD_SET_INTERNAL_BREAKPOINT64 SetInternalBreakpoint;
        DBGKD_GET_INTERNAL_BREAKPOINT64 GetInternalBreakpoint;
        DBGKD_GET_VERSION64 GetVersion64;
        DBGKD_BREAKPOINTEX BreakPointEx;
        DBGKD_READ_WRITE_MSR ReadWriteMsr;
        DBGKD_SEARCH_MEMORY SearchMemory;
        DBGKD_GET_SET_BUS_DATA GetSetBusData;
        DBGKD_FILL_MEMORY FillMemory;
        DBGKD_QUERY_MEMORY QueryMemory;
        DBGKD_SWITCH_PARTITION SwitchPartition;
        DBGKD_WRITE_CUSTOM_BREAKPOINT WriteCustomBreakpoint;
        DBGKD_CONTEXT_EX ContextEx;
    } u;
} DBGKD_MANIPULATE_STATE64, *PDBGKD_MANIPULATE_STATE64;

//
// File I/O Structure
//
typedef struct _DBGKD_CREATE_FILE
{
    ULONG DesiredAccess;
    ULONG FileAttributes;
    ULONG ShareAccess;
    ULONG CreateDisposition;
    ULONG CreateOptions;
    ULONG64 Handle;
    ULONG64 Length;
} DBGKD_CREATE_FILE, *PDBGKD_CREATE_FILE;

typedef struct _DBGKD_READ_FILE
{
    ULONG64 Handle;
    ULONG64 Offset;
    ULONG Length;
} DBGKD_READ_FILE, *PDBGKD_READ_FILE;

typedef struct _DBGKD_WRITE_FILE
{
    ULONG64 Handle;
    ULONG64 Offset;
    ULONG Length;
} DBGKD_WRITE_FILE, *PDBGKD_WRITE_FILE;

typedef struct _DBGKD_CLOSE_FILE
{
    ULONG64 Handle;
} DBGKD_CLOSE_FILE, *PDBGKD_CLOSE_FILE;

typedef struct _DBGKD_FILE_IO
{
    ULONG ApiNumber;
    ULONG Status;
    union
    {
        ULONG64 ReserveSpace[7];
        DBGKD_CREATE_FILE CreateFile;
        DBGKD_READ_FILE ReadFile;
        DBGKD_WRITE_FILE WriteFile;
        DBGKD_CLOSE_FILE CloseFile;
    } u;
} DBGKD_FILE_IO, *PDBGKD_FILE_IO;


//
// Control Request Structure
//
typedef struct _DBGKD_REQUEST_BREAKPOINT
{
    ULONG HardwareBreakPointNumber;
    ULONG Available;
} DBGKD_REQUEST_BREAKPOINT, *PDBGKD_REQUEST_BREAKPOINT;

typedef struct _DBGKD_RELEASE_BREAKPOINT
{
    ULONG HardwareBreakPointNumber;
    ULONG Released;
} DBGKD_RELEASE_BREAKPOINT, *PDBGKD_RELEASE_BREAKPOINT;

typedef struct _DBGKD_CONTROL_REQUEST
{
    ULONG ApiNumber;
    union
    {
        DBGKD_REQUEST_BREAKPOINT RequestBreakpoint;
        DBGKD_RELEASE_BREAKPOINT ReleaseBreakpoint;
    } u;
} DBGKD_CONTROL_REQUEST, *PDBGKD_CONTROL_REQUEST;

//
// Trace I/O Structure
//
typedef struct _DBGKD_PRINT_TRACE
{
    ULONG LengthOfData;
} DBGKD_PRINT_TRACE, *PDBGKD_PRINT_TRACE;

typedef struct _DBGKD_TRACE_IO
{
   ULONG ApiNumber;
   USHORT ProcessorLevel;
   USHORT Processor;
   union
   {
       ULONG64 ReserveSpace[7];
       DBGKD_PRINT_TRACE PrintTrace;
   } u;
} DBGKD_TRACE_IO, *PDBGKD_TRACE_IO;

typedef UCHAR KIRQL, * PKIRQL;

#define PASSIVE_LEVEL           0
#define LOW_LEVEL               0
#define APC_LEVEL               1
#define DISPATCH_LEVEL          2
#define CMCI_LEVEL              5
#define CLOCK_LEVEL             13
#define IPI_LEVEL               14
#define DRS_LEVEL               14
#define POWER_LEVEL             14
#define PROFILE_LEVEL           15
#define HIGH_LEVEL              15


//
// Breakpoint Status Flags
//
#define KD_BREAKPOINT_ACTIVE    0x01
#define KD_BREAKPOINT_PENDING   0x02
#define KD_BREAKPOINT_SUSPENDED 0x04
#define KD_BREAKPOINT_EXPIRED   0x08

#define KD_BREAKPOINT_TYPE        UCHAR
#define KD_BREAKPOINT_SIZE        sizeof(UCHAR)
#define KD_BREAKPOINT_VALUE       0xCC

#define KD_HIGHEST_USER_BREAKPOINT_ADDRESS  (PVOID)0x60000000  // MmHighestUserAddress

#define MM_PHYSICALMEMORY_SEGMENT           (0x1)
#define MM_DATAFILE_SEGMENT                 (0x2)
#define MM_SEGMENT_INDELETE                 (0x4)
#define MM_SEGMENT_INCREATE                 (0x8)
#define MM_IMAGE_SECTION_FLUSH_DELETE       (0x10)

#define KD_PRINT_MAX_BYTES 512

//
// MmDbgCopyMemory Flags
//
#define MMDBG_COPY_WRITE            0x00000001
#define MMDBG_COPY_PHYSICAL         0x00000002
#define MMDBG_COPY_UNSAFE           0x00000004
#define MMDBG_COPY_CACHED           0x00000008
#define MMDBG_COPY_UNCACHED         0x00000010
#define MMDBG_COPY_WRITE_COMBINED   0x00000020

//
// Maximum chunk size per copy
//
#define MMDBG_COPY_MAX_SIZE         0x8

#if defined(_X86_) // intenal for marea.c
#define MI_STATIC_MEMORY_AREAS              (14)
#else
#define MI_STATIC_MEMORY_AREAS              (13)
#endif

#define MEMORY_AREA_SECTION_VIEW            (1)
#ifdef NEWCC
#define MEMORY_AREA_CACHE                   (2)
#endif
#define MEMORY_AREA_OWNED_BY_ARM3           (15)
#define MEMORY_AREA_STATIC                  (0x80000000)

//
// Structure for Breakpoints
//
typedef struct _BREAKPOINT_ENTRY
{
	ULONG Flags;
	ULONG_PTR DirectoryTableBase;
	PVOID Address;
	KD_BREAKPOINT_TYPE Content;
} BREAKPOINT_ENTRY, * PBREAKPOINT_ENTRY;


//
// Debug Filter Levels
//
#define DPFLTR_ERROR_LEVEL                  0
#define DPFLTR_WARNING_LEVEL                1
#define DPFLTR_TRACE_LEVEL                  2
#define DPFLTR_INFO_LEVEL                   3
#define DPFLTR_MASK                         0x80000000

//
// Debug Status Codes
//
#define DBG_STATUS_CONTROL_C                1
#define DBG_STATUS_SYSRQ                    2
#define DBG_STATUS_BUGCHECK_FIRST           3
#define DBG_STATUS_BUGCHECK_SECOND          4
#define DBG_STATUS_FATAL                    5
#define DBG_STATUS_DEBUG_CONTROL            6
#define DBG_STATUS_WORKER                   7

//
// DebugService Control Types
//
#define BREAKPOINT_BREAK                    0
#define BREAKPOINT_PRINT                    1
#define BREAKPOINT_PROMPT                   2
#define BREAKPOINT_LOAD_SYMBOLS             3
#define BREAKPOINT_UNLOAD_SYMBOLS           4
#define BREAKPOINT_COMMAND_STRING           5

//
// Debug Control Codes for NtSystemDebugcontrol
//
typedef enum _SYSDBG_COMMAND
{
	SysDbgQueryModuleInformation = 0,
	SysDbgQueryTraceInformation = 1,
	SysDbgSetTracepoint = 2,
	SysDbgSetSpecialCall = 3,
	SysDbgClearSpecialCalls = 4,
	SysDbgQuerySpecialCalls = 5,
	SysDbgBreakPoint = 6,
	SysDbgQueryVersion = 7,
	SysDbgReadVirtual = 8,
	SysDbgWriteVirtual = 9,
	SysDbgReadPhysical = 10,
	SysDbgWritePhysical = 11,
	SysDbgReadControlSpace = 12,
	SysDbgWriteControlSpace = 13,
	SysDbgReadIoSpace = 14,
	SysDbgWriteIoSpace = 15,
	SysDbgReadMsr = 16,
	SysDbgWriteMsr = 17,
	SysDbgReadBusData = 18,
	SysDbgWriteBusData = 19,
	SysDbgCheckLowMemory = 20,
	SysDbgEnableKernelDebugger = 21,
	SysDbgDisableKernelDebugger = 22,
	SysDbgGetAutoKdEnable = 23,
	SysDbgSetAutoKdEnable = 24,
	SysDbgGetPrintBufferSize = 25,
	SysDbgSetPrintBufferSize = 26,
	SysDbgGetKdUmExceptionEnable = 27,
	SysDbgSetKdUmExceptionEnable = 28,
	SysDbgGetTriageDump = 29,
	SysDbgGetKdBlockEnable = 30,
	SysDbgSetKdBlockEnable = 31,
	SysDbgRegisterForUmBreakInfo = 32,
	SysDbgGetUmBreakPid = 33,
	SysDbgClearUmBreakPid = 34,
	SysDbgGetUmAttachPid = 35,
	SysDbgClearUmAttachPid = 36,
} SYSDBG_COMMAND;

//
// System Debugger Types
//
typedef struct _SYSDBG_PHYSICAL
{
	PHYSICAL_ADDRESS Address;
	PVOID Buffer;
	ULONG Request;
} SYSDBG_PHYSICAL, * PSYSDBG_PHYSICAL;

typedef struct _SYSDBG_VIRTUAL
{
	PVOID Address;
	PVOID Buffer;
	ULONG Request;
} SYSDBG_VIRTUAL, * PSYSDBG_VIRTUAL;

typedef struct _SYSDBG_CONTROL_SPACE
{
	ULONGLONG Address;
	PVOID Buffer;
	ULONG Request;
	ULONG Processor;
} SYSDBG_CONTROL_SPACE, * PSYSDBG_CONTROL_SPACE;

typedef struct _SYSDBG_MSR
{
	ULONG Address;
	ULONGLONG Data;
} SYSDBG_MSR, * PSYSDBG_MSR;


//
// KD Structures
//
typedef struct _KD_SYMBOLS_INFO
{
	PVOID BaseOfDll;
	ULONG_PTR ProcessId;
	ULONG CheckSum;
	ULONG SizeOfImage;
} KD_SYMBOLS_INFO, * PKD_SYMBOLS_INFO;


typedef struct _UEFI_SYMBOLS_INFO
{
    KD_SYMBOLS_INFO  SymbolInfo;
    WCHAR SymbolPathBuffer[KDP_MSG_BUFFER_SIZE];
} UEFI_SYMBOLS_INFO, * PUEFI_SYMBOLS_INFO;




//
// Trap Frame Definition
//
typedef struct _KTRAP_FRAME
{
	UINT64 P1Home;
	UINT64 P2Home;
	UINT64 P3Home;
	UINT64 P4Home;
	UINT64 P5;
	CHAR PreviousMode;
	UCHAR PreviousIrql;
	UCHAR FaultIndicator;
	UCHAR ExceptionActive;
	ULONG MxCsr;
	UINT64 Rax;
	UINT64 Rcx;
	UINT64 Rdx;
	UINT64 R8;
	UINT64 R9;
	UINT64 R10;
	UINT64 R11;
	union
	{
		UINT64 GsBase;
		UINT64 GsSwap;
	}u1;
	UINT128 Xmm0;
	UINT128 Xmm1;
	UINT128 Xmm2;
	UINT128 Xmm3;
	UINT128 Xmm4;
	UINT128 Xmm5;
	union
	{
		UINT64 FaultAddress;
		UINT64 ContextRecord;
		UINT64 TimeStampCKCL;
	}u2;
	UINT64 Dr0;
	UINT64 Dr1;
	UINT64 Dr2;
	UINT64 Dr3;
	UINT64 Dr6;
	UINT64 Dr7;
	union
	{
		struct
		{
			UINT64 DebugControl;
			UINT64 LastBranchToRip;
			UINT64 LastBranchFromRip;
			UINT64 LastExceptionToRip;
			UINT64 LastExceptionFromRip;
		}x;
		struct
		{
			UINT64 LastBranchControl;
			ULONG LastBranchMSR;
		}y;
	}u3;
	USHORT SegDs;
	USHORT SegEs;
	USHORT SegFs;
	USHORT SegGs;
	UINT64 TrapFrame;
	UINT64 Rbx;
	UINT64 Rdi;
	UINT64 Rsi;
	UINT64 Rbp;
	union
	{
		UINT64 ErrorCode;
		UINT64 ExceptionFrame;
		UINT64 TimeStampKlog;
	}u4;
	UINT64 Rip;
	USHORT SegCs;
	UCHAR Fill0;
	UCHAR Logging;
	USHORT Fill1[2];
	ULONG EFlags;
	ULONG Fill2;
	UINT64 Rsp;
	USHORT SegSs;
	USHORT Fill3;
	LONG CodePatchCycle;
} KTRAP_FRAME, * PKTRAP_FRAME;

//
// KEXCEPTION_FRAME
//
typedef struct _KEXCEPTION_FRAME
{
	ULONG64 P1Home;
	ULONG64 P2Home;
	ULONG64 P3Home;
	ULONG64 P4Home;
	ULONG64 P5;
#if (NTDDI_VERSION >= NTDDI_WIN8)
	ULONG64 Spare1;
#else
	ULONG64 InitialStack;
#endif
    UINT128 Xmm6;
	UINT128 Xmm7;
	UINT128 Xmm8;
	UINT128 Xmm9;
	UINT128 Xmm10;
	UINT128 Xmm11;
	UINT128 Xmm12;
	UINT128 Xmm13;
	UINT128 Xmm14;
	UINT128 Xmm15;
	ULONG64 TrapFrame;
#if (NTDDI_VERSION < NTDDI_WIN8)
	ULONG64 CallbackStack;
#endif
	ULONG64 OutputBuffer;
	ULONG64 OutputLength;
#if (NTDDI_VERSION >= NTDDI_WIN8)
	ULONG64 Spare2;
#endif
	ULONG64 MxCsr;
	ULONG64 Rbp;
	ULONG64 Rbx;
	ULONG64 Rdi;
	ULONG64 Rsi;
	ULONG64 R12;
	ULONG64 R13;
	ULONG64 R14;
	ULONG64 R15;
	ULONG64 Return;
} KEXCEPTION_FRAME, * PKEXCEPTION_FRAME;

typedef enum _MODE {
	KernelMode,
	UserMode,
	MaximumMode
} KPROCESSOR_MODE;


//typedef CHAR KPROCESSOR_MODE;
typedef LONG KPRIORITY;

typedef ULONG KDSTATUS;
#define KdPacketReceived     0
#define KdPacketTimedOut     1
#define KdPacketNeedsResend  2


#define FACILITY_DEBUGGER               0x1
#define FACILITY_RPC_RUNTIME            0x2
#define FACILITY_RPC_STUBS              0x3
#define FACILITY_IO_ERROR_CODE          0x4
#define FACILITY_TERMINAL_SERVER        0xA
#define FACILITY_USB_ERROR_CODE         0x10
#define FACILITY_HID_ERROR_CODE         0x11
#define FACILITY_FIREWIRE_ERROR_CODE    0x12
#define FACILITY_CLUSTER_ERROR_CODE     0x13
#define FACILITY_ACPI_ERROR_CODE        0x14
#define FACILITY_SXS_ERROR_CODE         0x15

/* Debug codes */

#define DBG_EXCEPTION_HANDLED             ((NTSTATUS)0x00010001)
#define DBG_CONTINUE                      ((NTSTATUS)0x00010002)
#define DBG_REPLY_LATER                   ((NTSTATUS)0x40010001)
#define DBG_UNABLE_TO_PROVIDE_HANDLE      ((NTSTATUS)0x40010002)
#define DBG_TERMINATE_THREAD              ((NTSTATUS)0x40010003)
#define DBG_TERMINATE_PROCESS             ((NTSTATUS)0x40010004)
#define DBG_CONTROL_C                     ((NTSTATUS)0x40010005)
#define DBG_PRINTEXCEPTION_C              ((NTSTATUS)0x40010006)
#define DBG_RIPEXCEPTION                  ((NTSTATUS)0x40010007)
#define DBG_CONTROL_BREAK                 ((NTSTATUS)0x40010008)
#define DBG_COMMAND_EXCEPTION             ((NTSTATUS)0x40010009)
#define DBG_EXCEPTION_NOT_HANDLED         ((NTSTATUS)0x80010001)
#define DBG_NO_STATE_CHANGE               ((NTSTATUS)0xC0010001)
#define DBG_APP_NOT_IDLE                  ((NTSTATUS)0xC0010002)

/* Exception codes */

#if !defined(STATUS_SUCCESS)
#define STATUS_SUCCESS                    ((NTSTATUS)0x00000000)
#endif
#define STATUS_SEVERITY_SUCCESS           0x0
#define STATUS_SEVERITY_INFORMATIONAL     0x1
#define STATUS_SEVERITY_WARNING           0x2
#define STATUS_SEVERITY_ERROR             0x3

#define STATUS_WAIT_1                             ((NTSTATUS)0x00000001)
#define STATUS_WAIT_2                             ((NTSTATUS)0x00000002)
#define STATUS_WAIT_3                             ((NTSTATUS)0x00000003)
#define STATUS_WAIT_63                            ((NTSTATUS)0x0000003f)
#define STATUS_ABANDONED                          ((NTSTATUS)0x00000080)
#define STATUS_ABANDONED_WAIT_0                   ((NTSTATUS)0x00000080)
#define STATUS_ABANDONED_WAIT_63                  ((NTSTATUS)0x000000BF)
#define STATUS_USER_APC                           ((NTSTATUS)0x000000C0)
#define STATUS_KERNEL_APC                         ((NTSTATUS)0x00000100)
#define STATUS_ALERTED                            ((NTSTATUS)0x00000101)
#define STATUS_TIMEOUT                            ((NTSTATUS)0x00000102)
#define STATUS_PENDING                            ((NTSTATUS)0x00000103)
#define STATUS_REPARSE                            ((NTSTATUS)0x00000104)
#define STATUS_MORE_ENTRIES                       ((NTSTATUS)0x00000105)
#define STATUS_NOT_ALL_ASSIGNED                   ((NTSTATUS)0x00000106)
#define STATUS_SOME_NOT_MAPPED                    ((NTSTATUS)0x00000107)
#define STATUS_OPLOCK_BREAK_IN_PROGRESS           ((NTSTATUS)0x00000108)
#define STATUS_VOLUME_MOUNTED                     ((NTSTATUS)0x00000109)
#define STATUS_RXACT_COMMITTED                    ((NTSTATUS)0x0000010A)
#define STATUS_NOTIFY_CLEANUP                     ((NTSTATUS)0x0000010B)
#define STATUS_NOTIFY_ENUM_DIR                    ((NTSTATUS)0x0000010C)
#define STATUS_NO_QUOTAS_FOR_ACCOUNT              ((NTSTATUS)0x0000010D)
#define STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED   ((NTSTATUS)0x0000010E)
#define STATUS_PAGE_FAULT_TRANSITION              ((NTSTATUS)0x00000110)
#define STATUS_PAGE_FAULT_DEMAND_ZERO             ((NTSTATUS)0x00000111)
#define STATUS_PAGE_FAULT_COPY_ON_WRITE           ((NTSTATUS)0x00000112)
#define STATUS_PAGE_FAULT_GUARD_PAGE              ((NTSTATUS)0x00000113)
#define STATUS_PAGE_FAULT_PAGING_FILE             ((NTSTATUS)0x00000114)
#define STATUS_CACHE_PAGE_LOCKED                  ((NTSTATUS)0x00000115)
#define STATUS_CRASH_DUMP                         ((NTSTATUS)0x00000116)
#define STATUS_BUFFER_ALL_ZEROS                   ((NTSTATUS)0x00000117)
#define STATUS_REPARSE_OBJECT                     ((NTSTATUS)0x00000118)
#define STATUS_RESOURCE_REQUIREMENTS_CHANGED      ((NTSTATUS)0x00000119)
#define STATUS_TRANSLATION_COMPLETE               ((NTSTATUS)0x00000120)
#define STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY    ((NTSTATUS)0x00000121)
#define STATUS_NOTHING_TO_TERMINATE               ((NTSTATUS)0x00000122)
#define STATUS_PROCESS_NOT_IN_JOB                 ((NTSTATUS)0x00000123)
#define STATUS_PROCESS_IN_JOB                     ((NTSTATUS)0x00000124)
#define STATUS_VOLSNAP_HIBERNATE_READY            ((NTSTATUS)0x00000125)
#define STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY ((NTSTATUS)0x00000126)
#define STATUS_FILE_LOCKED_WITH_ONLY_READERS      ((NTSTATUS)0x0000012A)
#define STATUS_FILE_LOCKED_WITH_WRITERS           ((NTSTATUS)0x0000012B)

#define STATUS_OBJECT_NAME_EXISTS              ((NTSTATUS)0x40000000)
#define STATUS_THREAD_WAS_SUSPENDED            ((NTSTATUS)0x40000001)
#define STATUS_WORKING_SET_LIMIT_RANGE         ((NTSTATUS)0x40000002)
#define STATUS_IMAGE_NOT_AT_BASE               ((NTSTATUS)0x40000003)
#define STATUS_RXACT_STATE_CREATED             ((NTSTATUS)0x40000004)
#define STATUS_SEGMENT_NOTIFICATION            ((NTSTATUS)0x40000005)
#define STATUS_LOCAL_USER_SESSION_KEY          ((NTSTATUS)0x40000006)
#define STATUS_BAD_CURRENT_DIRECTORY           ((NTSTATUS)0x40000007)
#define STATUS_SERIAL_MORE_WRITES              ((NTSTATUS)0x40000008)
#define STATUS_REGISTRY_RECOVERED              ((NTSTATUS)0x40000009)
#define STATUS_FT_READ_RECOVERY_FROM_BACKUP    ((NTSTATUS)0x4000000A)
#define STATUS_FT_WRITE_RECOVERY               ((NTSTATUS)0x4000000B)
#define STATUS_SERIAL_COUNTER_TIMEOUT          ((NTSTATUS)0x4000000C)
#define STATUS_NULL_LM_PASSWORD                ((NTSTATUS)0x4000000D)
#define STATUS_IMAGE_MACHINE_TYPE_MISMATCH     ((NTSTATUS)0x4000000E)
#define STATUS_RECEIVE_PARTIAL                 ((NTSTATUS)0x4000000F)
#define STATUS_RECEIVE_EXPEDITED               ((NTSTATUS)0x40000010)
#define STATUS_RECEIVE_PARTIAL_EXPEDITED       ((NTSTATUS)0x40000011)
#define STATUS_EVENT_DONE                      ((NTSTATUS)0x40000012)
#define STATUS_EVENT_PENDING                   ((NTSTATUS)0x40000013)
#define STATUS_CHECKING_FILE_SYSTEM            ((NTSTATUS)0x40000014)
#define STATUS_FATAL_APP_EXIT                  ((NTSTATUS)0x40000015)
#define STATUS_PREDEFINED_HANDLE               ((NTSTATUS)0x40000016)
#define STATUS_WAS_UNLOCKED                    ((NTSTATUS)0x40000017)
#define STATUS_SERVICE_NOTIFICATION            ((NTSTATUS)0x40000018)
#define STATUS_WAS_LOCKED                      ((NTSTATUS)0x40000019)
#define STATUS_LOG_HARD_ERROR                  ((NTSTATUS)0x4000001A)
#define STATUS_ALREADY_WIN32                   ((NTSTATUS)0x4000001B)
#define STATUS_WX86_UNSIMULATE                 ((NTSTATUS)0x4000001C)
#define STATUS_WX86_CONTINUE                   ((NTSTATUS)0x4000001D)
#define STATUS_WX86_SINGLE_STEP                ((NTSTATUS)0x4000001E)
#define STATUS_WX86_BREAKPOINT                 ((NTSTATUS)0x4000001F)
#define STATUS_WX86_EXCEPTION_CONTINUE         ((NTSTATUS)0x40000020)
#define STATUS_WX86_EXCEPTION_LASTCHANCE       ((NTSTATUS)0x40000021)
#define STATUS_WX86_EXCEPTION_CHAIN            ((NTSTATUS)0x40000022)
#define STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE ((NTSTATUS)0x40000023)
#define STATUS_NO_YIELD_PERFORMED              ((NTSTATUS)0x40000024)
#define STATUS_TIMER_RESUME_IGNORED            ((NTSTATUS)0x40000025)
#define STATUS_ARBITRATION_UNHANDLED           ((NTSTATUS)0x40000026)
#define STATUS_CARDBUS_NOT_SUPPORTED           ((NTSTATUS)0x40000027)
#define STATUS_WX86_CREATEWX86TIB              ((NTSTATUS)0x40000028)
#define STATUS_MP_PROCESSOR_MISMATCH           ((NTSTATUS)0x40000029)
#define STATUS_HIBERNATED                      ((NTSTATUS)0x4000002A)
#define STATUS_RESUME_HIBERNATION              ((NTSTATUS)0x4000002B)
#define STATUS_FIRMWARE_UPDATED                ((NTSTATUS)0x4000002C)
#define STATUS_DRIVERS_LEAKING_LOCKED_PAGES    ((NTSTATUS)0x4000002D)
#define STATUS_MESSAGE_RETRIEVED               ((NTSTATUS)0x4000002E)
#define STATUS_SYSTEM_POWERSTATE_TRANSITION    ((NTSTATUS)0x4000002F)
#define STATUS_ALPC_CHECK_COMPLETION_LIST      ((NTSTATUS)0x40000030)
#define STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION ((NTSTATUS)0x40000031)
#define STATUS_ACCESS_AUDIT_BY_POLICY          ((NTSTATUS)0x40000032)
#define STATUS_ABANDON_HIBERFILE               ((NTSTATUS)0x40000033)
#define STATUS_BIZRULES_NOT_ENABLED            ((NTSTATUS)0x40000034)
#define STATUS_FT_READ_FROM_COPY               ((NTSTATUS)0x40000035)
#define STATUS_IMAGE_AT_DIFFERENT_BASE         ((NTSTATUS)0x40000036)
#define STATUS_PATCH_DEFERRED                  ((NTSTATUS)0x40000037)
#define STATUS_WAKE_SYSTEM                     ((NTSTATUS)0x40000294)
#define STATUS_DS_SHUTTING_DOWN                ((NTSTATUS)0x40000370)
#define STATUS_DISK_REPAIR_REDIRECTED          ((NTSTATUS)0x40000807)

#define RPC_NT_UUID_LOCAL_ONLY           ((NTSTATUS)0x40020056)
#define RPC_NT_SEND_INCOMPLETE           ((NTSTATUS)0x400200AF)

#define STATUS_CTX_CDM_CONNECT           ((NTSTATUS)0x400A0004)
#define STATUS_CTX_CDM_DISCONNECT        ((NTSTATUS)0x400A0005)

#define STATUS_SXS_RELEASE_ACTIVATION_CONTEXT  ((NTSTATUS)0x4015000D)

#define STATUS_GUARD_PAGE_VIOLATION             ((NTSTATUS)0x80000001)
#define STATUS_DATATYPE_MISALIGNMENT            ((NTSTATUS)0x80000002)
#define STATUS_BREAKPOINT                       ((NTSTATUS)0x80000003)
#define STATUS_SINGLE_STEP                      ((NTSTATUS)0x80000004)
#define STATUS_BUFFER_OVERFLOW                  ((NTSTATUS)0x80000005)
#define STATUS_NO_MORE_FILES                    ((NTSTATUS)0x80000006)
#define STATUS_WAKE_SYSTEM_DEBUGGER             ((NTSTATUS)0x80000007)

#define STATUS_HANDLES_CLOSED                   ((NTSTATUS)0x8000000A)
#define STATUS_NO_INHERITANCE                   ((NTSTATUS)0x8000000B)
#define STATUS_GUID_SUBSTITUTION_MADE           ((NTSTATUS)0x8000000C)
#define STATUS_PARTIAL_COPY                     ((NTSTATUS)0x8000000D)
#define STATUS_DEVICE_PAPER_EMPTY               ((NTSTATUS)0x8000000E)
#define STATUS_DEVICE_POWERED_OFF               ((NTSTATUS)0x8000000F)
#define STATUS_DEVICE_OFF_LINE                  ((NTSTATUS)0x80000010)
#define STATUS_DEVICE_BUSY                      ((NTSTATUS)0x80000011)
#define STATUS_NO_MORE_EAS                      ((NTSTATUS)0x80000012)
#define STATUS_INVALID_EA_NAME                  ((NTSTATUS)0x80000013)
#define STATUS_EA_LIST_INCONSISTENT             ((NTSTATUS)0x80000014)
#define STATUS_INVALID_EA_FLAG                  ((NTSTATUS)0x80000015)
#define STATUS_VERIFY_REQUIRED                  ((NTSTATUS)0x80000016)
#define STATUS_EXTRANEOUS_INFORMATION           ((NTSTATUS)0x80000017)
#define STATUS_RXACT_COMMIT_NECESSARY           ((NTSTATUS)0x80000018)
#define STATUS_NO_MORE_ENTRIES                  ((NTSTATUS)0x8000001A)
#define STATUS_FILEMARK_DETECTED                ((NTSTATUS)0x8000001B)
#define STATUS_MEDIA_CHANGED                    ((NTSTATUS)0x8000001C)
#define STATUS_BUS_RESET                        ((NTSTATUS)0x8000001D)
#define STATUS_END_OF_MEDIA                     ((NTSTATUS)0x8000001E)
#define STATUS_BEGINNING_OF_MEDIA               ((NTSTATUS)0x8000001F)
#define STATUS_MEDIA_CHECK                      ((NTSTATUS)0x80000020)
#define STATUS_SETMARK_DETECTED                 ((NTSTATUS)0x80000021)
#define STATUS_NO_DATA_DETECTED                 ((NTSTATUS)0x80000022)
#define STATUS_REDIRECTOR_HAS_OPEN_HANDLES      ((NTSTATUS)0x80000023)
#define STATUS_SERVER_HAS_OPEN_HANDLES          ((NTSTATUS)0x80000024)
#define STATUS_ALREADY_DISCONNECTED             ((NTSTATUS)0x80000025)
#define STATUS_LONGJUMP                         ((NTSTATUS)0x80000026)
#define STATUS_CLEANER_CARTRIDGE_INSTALLED      ((NTSTATUS)0x80000027)
#define STATUS_PLUGPLAY_QUERY_VETOED            ((NTSTATUS)0x80000028)
#define STATUS_UNWIND_CONSOLIDATE               ((NTSTATUS)0x80000029)
#define STATUS_REGISTRY_HIVE_RECOVERED          ((NTSTATUS)0x8000002A)
#define STATUS_DLL_MIGHT_BE_INSECURE            ((NTSTATUS)0x8000002B)
#define STATUS_DLL_MIGHT_BE_INCOMPATIBLE        ((NTSTATUS)0x8000002C)
#define STATUS_STOPPED_ON_SYMLINK               ((NTSTATUS)0x8000002D)

#define STATUS_DEVICE_REQUIRES_CLEANING         ((NTSTATUS)0x80000288)
#define STATUS_DEVICE_DOOR_OPEN                 ((NTSTATUS)0x80000289)

#define STATUS_DATA_LOST_REPAIR                 ((NTSTATUS)0x80000803)

#define STATUS_CLUSTER_NODE_ALREADY_UP          ((NTSTATUS)0x80130001)
#define STATUS_CLUSTER_NODE_ALREADY_DOWN        ((NTSTATUS)0x80130002)
#define STATUS_CLUSTER_NETWORK_ALREADY_ONLINE   ((NTSTATUS)0x80130003)
#define STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE  ((NTSTATUS)0x80130004)
#define STATUS_CLUSTER_NODE_ALREADY_MEMBER      ((NTSTATUS)0x80130005)

#define STATUS_WAIT_0                           ((NTSTATUS)0x00000000)
#define STATUS_UNSUCCESSFUL                     ((NTSTATUS)0xC0000001)
#define STATUS_NOT_IMPLEMENTED                  ((NTSTATUS)0xC0000002)
#define STATUS_INVALID_INFO_CLASS               ((NTSTATUS)0xC0000003)
#define STATUS_INFO_LENGTH_MISMATCH             ((NTSTATUS)0xC0000004)
#define STATUS_ACCESS_VIOLATION                 ((NTSTATUS)0xC0000005)
#define STATUS_IN_PAGE_ERROR                    ((NTSTATUS)0xC0000006)
#define STATUS_PAGEFILE_QUOTA                   ((NTSTATUS)0xC0000007)
#define STATUS_INVALID_HANDLE                   ((NTSTATUS)0xC0000008)
#define STATUS_BAD_INITIAL_STACK                ((NTSTATUS)0xC0000009)
#define STATUS_BAD_INITIAL_PC                   ((NTSTATUS)0xC000000A)
#define STATUS_INVALID_CID                      ((NTSTATUS)0xC000000B)
#define STATUS_TIMER_NOT_CANCELED               ((NTSTATUS)0xC000000C)
#define STATUS_INVALID_PARAMETER                ((NTSTATUS)0xC000000D)
#define STATUS_NO_SUCH_DEVICE                   ((NTSTATUS)0xC000000E)
#define STATUS_NO_SUCH_FILE                     ((NTSTATUS)0xC000000F)
#define STATUS_INVALID_DEVICE_REQUEST           ((NTSTATUS)0xC0000010)
#define STATUS_END_OF_FILE                      ((NTSTATUS)0xC0000011)
#define STATUS_WRONG_VOLUME                     ((NTSTATUS)0xC0000012)
#define STATUS_NO_MEDIA_IN_DEVICE               ((NTSTATUS)0xC0000013)
#define STATUS_UNRECOGNIZED_MEDIA               ((NTSTATUS)0xC0000014)
#define STATUS_NONEXISTENT_SECTOR               ((NTSTATUS)0xC0000015)
#define STATUS_MORE_PROCESSING_REQUIRED         ((NTSTATUS)0xC0000016)
#define STATUS_NO_MEMORY                        ((NTSTATUS)0xC0000017)
#define STATUS_CONFLICTING_ADDRESSES            ((NTSTATUS)0xC0000018)
#define STATUS_NOT_MAPPED_VIEW                  ((NTSTATUS)0xC0000019)
#define STATUS_UNABLE_TO_FREE_VM                ((NTSTATUS)0xC000001A)
#define STATUS_UNABLE_TO_DELETE_SECTION         ((NTSTATUS)0xC000001B)
#define STATUS_INVALID_SYSTEM_SERVICE           ((NTSTATUS)0xC000001C)
#define STATUS_ILLEGAL_INSTRUCTION              ((NTSTATUS)0xC000001D)
#define STATUS_INVALID_LOCK_SEQUENCE            ((NTSTATUS)0xC000001E)
#define STATUS_INVALID_VIEW_SIZE                ((NTSTATUS)0xC000001F)
#define STATUS_INVALID_FILE_FOR_SECTION         ((NTSTATUS)0xC0000020)
#define STATUS_ALREADY_COMMITTED                ((NTSTATUS)0xC0000021)
#define STATUS_ACCESS_DENIED                    ((NTSTATUS)0xC0000022)
#define STATUS_BUFFER_TOO_SMALL                 ((NTSTATUS)0xC0000023)
#define STATUS_OBJECT_TYPE_MISMATCH             ((NTSTATUS)0xC0000024)
#define STATUS_NONCONTINUABLE_EXCEPTION         ((NTSTATUS)0xC0000025)
#define STATUS_INVALID_DISPOSITION              ((NTSTATUS)0xC0000026)
#define STATUS_UNWIND                           ((NTSTATUS)0xC0000027)
#define STATUS_BAD_STACK                        ((NTSTATUS)0xC0000028)
#define STATUS_INVALID_UNWIND_TARGET            ((NTSTATUS)0xC0000029)
#define STATUS_NOT_LOCKED                       ((NTSTATUS)0xC000002A)
#define STATUS_PARITY_ERROR                     ((NTSTATUS)0xC000002B)
#define STATUS_UNABLE_TO_DECOMMIT_VM            ((NTSTATUS)0xC000002C)
#define STATUS_NOT_COMMITTED                    ((NTSTATUS)0xC000002D)
#define STATUS_INVALID_PORT_ATTRIBUTES          ((NTSTATUS)0xC000002E)
#define STATUS_PORT_MESSAGE_TOO_LONG            ((NTSTATUS)0xC000002F)
#define STATUS_INVALID_PARAMETER_MIX            ((NTSTATUS)0xC0000030)
#define STATUS_INVALID_QUOTA_LOWER              ((NTSTATUS)0xC0000031)
#define STATUS_DISK_CORRUPT_ERROR               ((NTSTATUS)0xC0000032)
#define STATUS_OBJECT_NAME_INVALID              ((NTSTATUS)0xC0000033)
#define STATUS_OBJECT_NAME_NOT_FOUND            ((NTSTATUS)0xC0000034)
#define STATUS_OBJECT_NAME_COLLISION            ((NTSTATUS)0xC0000035)
#define STATUS_PORT_DISCONNECTED                ((NTSTATUS)0xC0000037)
#define STATUS_DEVICE_ALREADY_ATTACHED          ((NTSTATUS)0xC0000038)
#define STATUS_OBJECT_PATH_INVALID              ((NTSTATUS)0xC0000039)
#define STATUS_OBJECT_PATH_NOT_FOUND            ((NTSTATUS)0xC000003A)
#define STATUS_OBJECT_PATH_SYNTAX_BAD           ((NTSTATUS)0xC000003B)
#define STATUS_DATA_OVERRUN                     ((NTSTATUS)0xC000003C)
#define STATUS_DATA_LATE_ERROR                  ((NTSTATUS)0xC000003D)
#define STATUS_DATA_ERROR                       ((NTSTATUS)0xC000003E)
#define STATUS_CRC_ERROR                        ((NTSTATUS)0xC000003F)
#define STATUS_SECTION_TOO_BIG                  ((NTSTATUS)0xC0000040)
#define STATUS_PORT_CONNECTION_REFUSED          ((NTSTATUS)0xC0000041)
#define STATUS_INVALID_PORT_HANDLE              ((NTSTATUS)0xC0000042)
#define STATUS_SHARING_VIOLATION                ((NTSTATUS)0xC0000043)
#define STATUS_QUOTA_EXCEEDED                   ((NTSTATUS)0xC0000044)
#define STATUS_INVALID_PAGE_PROTECTION          ((NTSTATUS)0xC0000045)
#define STATUS_MUTANT_NOT_OWNED                 ((NTSTATUS)0xC0000046)
#define STATUS_SEMAPHORE_LIMIT_EXCEEDED         ((NTSTATUS)0xC0000047)
#define STATUS_PORT_ALREADY_SET                 ((NTSTATUS)0xC0000048)
#define STATUS_SECTION_NOT_IMAGE                ((NTSTATUS)0xC0000049)
#define STATUS_SUSPEND_COUNT_EXCEEDED           ((NTSTATUS)0xC000004A)
#define STATUS_THREAD_IS_TERMINATING            ((NTSTATUS)0xC000004B)
#define STATUS_BAD_WORKING_SET_LIMIT            ((NTSTATUS)0xC000004C)
#define STATUS_INCOMPATIBLE_FILE_MAP            ((NTSTATUS)0xC000004D)
#define STATUS_SECTION_PROTECTION               ((NTSTATUS)0xC000004E)
#define STATUS_EAS_NOT_SUPPORTED                ((NTSTATUS)0xC000004F)
#define STATUS_EA_TOO_LARGE                     ((NTSTATUS)0xC0000050)
#define STATUS_NONEXISTENT_EA_ENTRY             ((NTSTATUS)0xC0000051)
#define STATUS_NO_EAS_ON_FILE                   ((NTSTATUS)0xC0000052)
#define STATUS_EA_CORRUPT_ERROR                 ((NTSTATUS)0xC0000053)
#define STATUS_FILE_LOCK_CONFLICT               ((NTSTATUS)0xC0000054)
#define STATUS_LOCK_NOT_GRANTED                 ((NTSTATUS)0xC0000055)
#define STATUS_DELETE_PENDING                   ((NTSTATUS)0xC0000056)
#define STATUS_CTL_FILE_NOT_SUPPORTED           ((NTSTATUS)0xC0000057)
#define STATUS_UNKNOWN_REVISION                 ((NTSTATUS)0xC0000058)
#define STATUS_REVISION_MISMATCH                ((NTSTATUS)0xC0000059)
#define STATUS_INVALID_OWNER                    ((NTSTATUS)0xC000005A)
#define STATUS_INVALID_PRIMARY_GROUP            ((NTSTATUS)0xC000005B)
#define STATUS_NO_IMPERSONATION_TOKEN           ((NTSTATUS)0xC000005C)
#define STATUS_CANT_DISABLE_MANDATORY           ((NTSTATUS)0xC000005D)
#define STATUS_NO_LOGON_SERVERS                 ((NTSTATUS)0xC000005E)
#define STATUS_NO_SUCH_LOGON_SESSION            ((NTSTATUS)0xC000005F)
#define STATUS_NO_SUCH_PRIVILEGE                ((NTSTATUS)0xC0000060)
#define STATUS_PRIVILEGE_NOT_HELD               ((NTSTATUS)0xC0000061)
#define STATUS_INVALID_ACCOUNT_NAME             ((NTSTATUS)0xC0000062)
#define STATUS_USER_EXISTS                      ((NTSTATUS)0xC0000063)
#define STATUS_NO_SUCH_USER                     ((NTSTATUS)0xC0000064)
#define STATUS_GROUP_EXISTS                     ((NTSTATUS)0xC0000065)
#define STATUS_NO_SUCH_GROUP                    ((NTSTATUS)0xC0000066)
#define STATUS_MEMBER_IN_GROUP                  ((NTSTATUS)0xC0000067)
#define STATUS_MEMBER_NOT_IN_GROUP              ((NTSTATUS)0xC0000068)
#define STATUS_LAST_ADMIN                       ((NTSTATUS)0xC0000069)
#define STATUS_WRONG_PASSWORD                   ((NTSTATUS)0xC000006A)
#define STATUS_ILL_FORMED_PASSWORD              ((NTSTATUS)0xC000006B)
#define STATUS_PASSWORD_RESTRICTION             ((NTSTATUS)0xC000006C)
#define STATUS_LOGON_FAILURE                    ((NTSTATUS)0xC000006D)
#define STATUS_ACCOUNT_RESTRICTION              ((NTSTATUS)0xC000006E)
#define STATUS_INVALID_LOGON_HOURS              ((NTSTATUS)0xC000006F)
#define STATUS_INVALID_WORKSTATION              ((NTSTATUS)0xC0000070)
#define STATUS_PASSWORD_EXPIRED                 ((NTSTATUS)0xC0000071)
#define STATUS_ACCOUNT_DISABLED                 ((NTSTATUS)0xC0000072)
#define STATUS_NONE_MAPPED                      ((NTSTATUS)0xC0000073)
#define STATUS_TOO_MANY_LUIDS_REQUESTED         ((NTSTATUS)0xC0000074)
#define STATUS_LUIDS_EXHAUSTED                  ((NTSTATUS)0xC0000075)
#define STATUS_INVALID_SUB_AUTHORITY            ((NTSTATUS)0xC0000076)
#define STATUS_INVALID_ACL                      ((NTSTATUS)0xC0000077)
#define STATUS_INVALID_SID                      ((NTSTATUS)0xC0000078)
#define STATUS_INVALID_SECURITY_DESCR           ((NTSTATUS)0xC0000079)
#define STATUS_PROCEDURE_NOT_FOUND              ((NTSTATUS)0xC000007A)
#define STATUS_INVALID_IMAGE_FORMAT             ((NTSTATUS)0xC000007B)
#define STATUS_NO_TOKEN                         ((NTSTATUS)0xC000007C)
#define STATUS_BAD_INHERITANCE_ACL              ((NTSTATUS)0xC000007D)
#define STATUS_RANGE_NOT_LOCKED                 ((NTSTATUS)0xC000007E)
#define STATUS_DISK_FULL                        ((NTSTATUS)0xC000007F)
#define STATUS_SERVER_DISABLED                  ((NTSTATUS)0xC0000080)
#define STATUS_SERVER_NOT_DISABLED              ((NTSTATUS)0xC0000081)
#define STATUS_TOO_MANY_GUIDS_REQUESTED         ((NTSTATUS)0xC0000082)
#define STATUS_GUIDS_EXHAUSTED                  ((NTSTATUS)0xC0000083)
#define STATUS_INVALID_ID_AUTHORITY             ((NTSTATUS)0xC0000084)
#define STATUS_AGENTS_EXHAUSTED                 ((NTSTATUS)0xC0000085)
#define STATUS_INVALID_VOLUME_LABEL             ((NTSTATUS)0xC0000086)
#define STATUS_SECTION_NOT_EXTENDED             ((NTSTATUS)0xC0000087)
#define STATUS_NOT_MAPPED_DATA                  ((NTSTATUS)0xC0000088)
#define STATUS_RESOURCE_DATA_NOT_FOUND          ((NTSTATUS)0xC0000089)
#define STATUS_RESOURCE_TYPE_NOT_FOUND          ((NTSTATUS)0xC000008A)
#define STATUS_RESOURCE_NAME_NOT_FOUND          ((NTSTATUS)0xC000008B)
#define STATUS_ARRAY_BOUNDS_EXCEEDED            ((NTSTATUS)0xC000008C)
#define STATUS_FLOAT_DENORMAL_OPERAND           ((NTSTATUS)0xC000008D)
#define STATUS_FLOAT_DIVIDE_BY_ZERO             ((NTSTATUS)0xC000008E)
#define STATUS_FLOAT_INEXACT_RESULT             ((NTSTATUS)0xC000008F)
#define STATUS_FLOAT_INVALID_OPERATION          ((NTSTATUS)0xC0000090)
#define STATUS_FLOAT_OVERFLOW                   ((NTSTATUS)0xC0000091)
#define STATUS_FLOAT_STACK_CHECK                ((NTSTATUS)0xC0000092)
#define STATUS_FLOAT_UNDERFLOW                  ((NTSTATUS)0xC0000093)
#define STATUS_INTEGER_DIVIDE_BY_ZERO           ((NTSTATUS)0xC0000094)
#define STATUS_INTEGER_OVERFLOW                 ((NTSTATUS)0xC0000095)
#define STATUS_PRIVILEGED_INSTRUCTION           ((NTSTATUS)0xC0000096)
#define STATUS_TOO_MANY_PAGING_FILES            ((NTSTATUS)0xC0000097)
#define STATUS_FILE_INVALID                     ((NTSTATUS)0xC0000098)
#define STATUS_ALLOTTED_SPACE_EXCEEDED          ((NTSTATUS)0xC0000099)
#define STATUS_INSUFFICIENT_RESOURCES           ((NTSTATUS)0xC000009A)
#define STATUS_DFS_EXIT_PATH_FOUND              ((NTSTATUS)0xC000009B)
#define STATUS_DEVICE_DATA_ERROR                ((NTSTATUS)0xC000009C)
#define STATUS_DEVICE_NOT_CONNECTED             ((NTSTATUS)0xC000009D)
#define STATUS_DEVICE_POWER_FAILURE             ((NTSTATUS)0xC000009E)
#define STATUS_FREE_VM_NOT_AT_BASE              ((NTSTATUS)0xC000009F)
#define STATUS_MEMORY_NOT_ALLOCATED             ((NTSTATUS)0xC00000A0)
#define STATUS_WORKING_SET_QUOTA                ((NTSTATUS)0xC00000A1)
#define STATUS_MEDIA_WRITE_PROTECTED            ((NTSTATUS)0xC00000A2)
#define STATUS_DEVICE_NOT_READY                 ((NTSTATUS)0xC00000A3)
#define STATUS_INVALID_GROUP_ATTRIBUTES         ((NTSTATUS)0xC00000A4)
#define STATUS_BAD_IMPERSONATION_LEVEL          ((NTSTATUS)0xC00000A5)
#define STATUS_CANT_OPEN_ANONYMOUS              ((NTSTATUS)0xC00000A6)
#define STATUS_BAD_VALIDATION_CLASS             ((NTSTATUS)0xC00000A7)
#define STATUS_BAD_TOKEN_TYPE                   ((NTSTATUS)0xC00000A8)
#define STATUS_BAD_MASTER_BOOT_RECORD           ((NTSTATUS)0xC00000A9)
#define STATUS_INSTRUCTION_MISALIGNMENT         ((NTSTATUS)0xC00000AA)
#define STATUS_INSTANCE_NOT_AVAILABLE           ((NTSTATUS)0xC00000AB)
#define STATUS_PIPE_NOT_AVAILABLE               ((NTSTATUS)0xC00000AC)
#define STATUS_INVALID_PIPE_STATE               ((NTSTATUS)0xC00000AD)
#define STATUS_PIPE_BUSY                        ((NTSTATUS)0xC00000AE)
#define STATUS_ILLEGAL_FUNCTION                 ((NTSTATUS)0xC00000AF)
#define STATUS_PIPE_DISCONNECTED                ((NTSTATUS)0xC00000B0)
#define STATUS_PIPE_CLOSING                     ((NTSTATUS)0xC00000B1)
#define STATUS_PIPE_CONNECTED                   ((NTSTATUS)0xC00000B2)
#define STATUS_PIPE_LISTENING                   ((NTSTATUS)0xC00000B3)
#define STATUS_INVALID_READ_MODE                ((NTSTATUS)0xC00000B4)
#define STATUS_IO_TIMEOUT                       ((NTSTATUS)0xC00000B5)
#define STATUS_FILE_FORCED_CLOSED               ((NTSTATUS)0xC00000B6)
#define STATUS_PROFILING_NOT_STARTED            ((NTSTATUS)0xC00000B7)
#define STATUS_PROFILING_NOT_STOPPED            ((NTSTATUS)0xC00000B8)
#define STATUS_COULD_NOT_INTERPRET              ((NTSTATUS)0xC00000B9)
#define STATUS_FILE_IS_A_DIRECTORY              ((NTSTATUS)0xC00000BA)
#define STATUS_NOT_SUPPORTED                    ((NTSTATUS)0xC00000BB)
#define STATUS_REMOTE_NOT_LISTENING             ((NTSTATUS)0xC00000BC)
#define STATUS_DUPLICATE_NAME                   ((NTSTATUS)0xC00000BD)
#define STATUS_BAD_NETWORK_PATH                 ((NTSTATUS)0xC00000BE)
#define STATUS_NETWORK_BUSY                     ((NTSTATUS)0xC00000BF)
#define STATUS_DEVICE_DOES_NOT_EXIST            ((NTSTATUS)0xC00000C0)
#define STATUS_TOO_MANY_COMMANDS                ((NTSTATUS)0xC00000C1)
#define STATUS_ADAPTER_HARDWARE_ERROR           ((NTSTATUS)0xC00000C2)
#define STATUS_INVALID_NETWORK_RESPONSE         ((NTSTATUS)0xC00000C3)
#define STATUS_UNEXPECTED_NETWORK_ERROR         ((NTSTATUS)0xC00000C4)
#define STATUS_BAD_REMOTE_ADAPTER               ((NTSTATUS)0xC00000C5)
#define STATUS_PRINT_QUEUE_FULL                 ((NTSTATUS)0xC00000C6)
#define STATUS_NO_SPOOL_SPACE                   ((NTSTATUS)0xC00000C7)
#define STATUS_PRINT_CANCELLED                  ((NTSTATUS)0xC00000C8)
#define STATUS_NETWORK_NAME_DELETED             ((NTSTATUS)0xC00000C9)
#define STATUS_NETWORK_ACCESS_DENIED            ((NTSTATUS)0xC00000CA)
#define STATUS_BAD_DEVICE_TYPE                  ((NTSTATUS)0xC00000CB)
#define STATUS_BAD_NETWORK_NAME                 ((NTSTATUS)0xC00000CC)
#define STATUS_TOO_MANY_NAMES                   ((NTSTATUS)0xC00000CD)
#define STATUS_TOO_MANY_SESSIONS                ((NTSTATUS)0xC00000CE)
#define STATUS_SHARING_PAUSED                   ((NTSTATUS)0xC00000CF)
#define STATUS_REQUEST_NOT_ACCEPTED             ((NTSTATUS)0xC00000D0)
#define STATUS_REDIRECTOR_PAUSED                ((NTSTATUS)0xC00000D1)
#define STATUS_NET_WRITE_FAULT                  ((NTSTATUS)0xC00000D2)
#define STATUS_PROFILING_AT_LIMIT               ((NTSTATUS)0xC00000D3)
#define STATUS_NOT_SAME_DEVICE                  ((NTSTATUS)0xC00000D4)
#define STATUS_FILE_RENAMED                     ((NTSTATUS)0xC00000D5)
#define STATUS_VIRTUAL_CIRCUIT_CLOSED           ((NTSTATUS)0xC00000D6)
#define STATUS_NO_SECURITY_ON_OBJECT            ((NTSTATUS)0xC00000D7)
#define STATUS_CANT_WAIT                        ((NTSTATUS)0xC00000D8)
#define STATUS_PIPE_EMPTY                       ((NTSTATUS)0xC00000D9)
#define STATUS_CANT_ACCESS_DOMAIN_INFO          ((NTSTATUS)0xC00000DA)
#define STATUS_CANT_TERMINATE_SELF              ((NTSTATUS)0xC00000DB)
#define STATUS_INVALID_SERVER_STATE             ((NTSTATUS)0xC00000DC)
#define STATUS_INVALID_DOMAIN_STATE             ((NTSTATUS)0xC00000DD)
#define STATUS_INVALID_DOMAIN_ROLE              ((NTSTATUS)0xC00000DE)
#define STATUS_NO_SUCH_DOMAIN                   ((NTSTATUS)0xC00000DF)
#define STATUS_DOMAIN_EXISTS                    ((NTSTATUS)0xC00000E0)
#define STATUS_DOMAIN_LIMIT_EXCEEDED            ((NTSTATUS)0xC00000E1)
#define STATUS_OPLOCK_NOT_GRANTED               ((NTSTATUS)0xC00000E2)
#define STATUS_INVALID_OPLOCK_PROTOCOL          ((NTSTATUS)0xC00000E3)
#define STATUS_INTERNAL_DB_CORRUPTION           ((NTSTATUS)0xC00000E4)
#define STATUS_INTERNAL_ERROR                   ((NTSTATUS)0xC00000E5)
#define STATUS_GENERIC_NOT_MAPPED               ((NTSTATUS)0xC00000E6)
#define STATUS_BAD_DESCRIPTOR_FORMAT            ((NTSTATUS)0xC00000E7)
#define STATUS_INVALID_USER_BUFFER              ((NTSTATUS)0xC00000E8)
#define STATUS_UNEXPECTED_IO_ERROR              ((NTSTATUS)0xC00000E9)
#define STATUS_UNEXPECTED_MM_CREATE_ERR         ((NTSTATUS)0xC00000EA)
#define STATUS_UNEXPECTED_MM_MAP_ERROR          ((NTSTATUS)0xC00000EB)
#define STATUS_UNEXPECTED_MM_EXTEND_ERR         ((NTSTATUS)0xC00000EC)
#define STATUS_NOT_LOGON_PROCESS                ((NTSTATUS)0xC00000ED)
#define STATUS_LOGON_SESSION_EXISTS             ((NTSTATUS)0xC00000EE)
#define STATUS_INVALID_PARAMETER_1              ((NTSTATUS)0xC00000EF)
#define STATUS_INVALID_PARAMETER_2              ((NTSTATUS)0xC00000F0)
#define STATUS_INVALID_PARAMETER_3              ((NTSTATUS)0xC00000F1)
#define STATUS_INVALID_PARAMETER_4              ((NTSTATUS)0xC00000F2)
#define STATUS_INVALID_PARAMETER_5              ((NTSTATUS)0xC00000F3)
#define STATUS_INVALID_PARAMETER_6              ((NTSTATUS)0xC00000F4)
#define STATUS_INVALID_PARAMETER_7              ((NTSTATUS)0xC00000F5)
#define STATUS_INVALID_PARAMETER_8              ((NTSTATUS)0xC00000F6)
#define STATUS_INVALID_PARAMETER_9              ((NTSTATUS)0xC00000F7)
#define STATUS_INVALID_PARAMETER_10             ((NTSTATUS)0xC00000F8)
#define STATUS_INVALID_PARAMETER_11             ((NTSTATUS)0xC00000F9)
#define STATUS_INVALID_PARAMETER_12             ((NTSTATUS)0xC00000FA)
#define STATUS_REDIRECTOR_NOT_STARTED           ((NTSTATUS)0xC00000FB)
#define STATUS_REDIRECTOR_STARTED               ((NTSTATUS)0xC00000FC)
#define STATUS_STACK_OVERFLOW                   ((NTSTATUS)0xC00000FD)
#define STATUS_NO_SUCH_PACKAGE                  ((NTSTATUS)0xC00000FE)
#define STATUS_BAD_FUNCTION_TABLE               ((NTSTATUS)0xC00000FF)
#define STATUS_VARIABLE_NOT_FOUND               ((NTSTATUS)0xC0000100)
#define STATUS_DIRECTORY_NOT_EMPTY              ((NTSTATUS)0xC0000101)
#define STATUS_FILE_CORRUPT_ERROR               ((NTSTATUS)0xC0000102)
#define STATUS_NOT_A_DIRECTORY                  ((NTSTATUS)0xC0000103)
#define STATUS_BAD_LOGON_SESSION_STATE          ((NTSTATUS)0xC0000104)
#define STATUS_LOGON_SESSION_COLLISION          ((NTSTATUS)0xC0000105)
#define STATUS_NAME_TOO_LONG                    ((NTSTATUS)0xC0000106)
#define STATUS_FILES_OPEN                       ((NTSTATUS)0xC0000107)
#define STATUS_CONNECTION_IN_USE                ((NTSTATUS)0xC0000108)
#define STATUS_MESSAGE_NOT_FOUND                ((NTSTATUS)0xC0000109)
#define STATUS_PROCESS_IS_TERMINATING           ((NTSTATUS)0xC000010A)
#define STATUS_INVALID_LOGON_TYPE               ((NTSTATUS)0xC000010B)
#define STATUS_NO_GUID_TRANSLATION              ((NTSTATUS)0xC000010C)
#define STATUS_CANNOT_IMPERSONATE               ((NTSTATUS)0xC000010D)
#define STATUS_IMAGE_ALREADY_LOADED             ((NTSTATUS)0xC000010E)
#define STATUS_ABIOS_NOT_PRESENT                ((NTSTATUS)0xC000010F)
#define STATUS_ABIOS_LID_NOT_EXIST              ((NTSTATUS)0xC0000110)
#define STATUS_ABIOS_LID_ALREADY_OWNED          ((NTSTATUS)0xC0000111)
#define STATUS_ABIOS_NOT_LID_OWNER              ((NTSTATUS)0xC0000112)
#define STATUS_ABIOS_INVALID_COMMAND            ((NTSTATUS)0xC0000113)
#define STATUS_ABIOS_INVALID_LID                ((NTSTATUS)0xC0000114)
#define STATUS_ABIOS_SELECTOR_NOT_AVAILABLE     ((NTSTATUS)0xC0000115)
#define STATUS_ABIOS_INVALID_SELECTOR           ((NTSTATUS)0xC0000116)
#define STATUS_NO_LDT                           ((NTSTATUS)0xC0000117)
#define STATUS_INVALID_LDT_SIZE                 ((NTSTATUS)0xC0000118)
#define STATUS_INVALID_LDT_OFFSET               ((NTSTATUS)0xC0000119)
#define STATUS_INVALID_LDT_DESCRIPTOR           ((NTSTATUS)0xC000011A)
#define STATUS_INVALID_IMAGE_NE_FORMAT          ((NTSTATUS)0xC000011B)
#define STATUS_RXACT_INVALID_STATE              ((NTSTATUS)0xC000011C)
#define STATUS_RXACT_COMMIT_FAILURE             ((NTSTATUS)0xC000011D)
#define STATUS_MAPPED_FILE_SIZE_ZERO            ((NTSTATUS)0xC000011E)
#define STATUS_TOO_MANY_OPENED_FILES            ((NTSTATUS)0xC000011F)
#define STATUS_CANCELLED                        ((NTSTATUS)0xC0000120)
#define STATUS_CANNOT_DELETE                    ((NTSTATUS)0xC0000121)
#define STATUS_INVALID_COMPUTER_NAME            ((NTSTATUS)0xC0000122)
#define STATUS_FILE_DELETED                     ((NTSTATUS)0xC0000123)
#define STATUS_SPECIAL_ACCOUNT                  ((NTSTATUS)0xC0000124)
#define STATUS_SPECIAL_GROUP                    ((NTSTATUS)0xC0000125)
#define STATUS_SPECIAL_USER                     ((NTSTATUS)0xC0000126)
#define STATUS_MEMBERS_PRIMARY_GROUP            ((NTSTATUS)0xC0000127)
#define STATUS_FILE_CLOSED                      ((NTSTATUS)0xC0000128)
#define STATUS_TOO_MANY_THREADS                 ((NTSTATUS)0xC0000129)
#define STATUS_THREAD_NOT_IN_PROCESS            ((NTSTATUS)0xC000012A)
#define STATUS_TOKEN_ALREADY_IN_USE             ((NTSTATUS)0xC000012B)
#define STATUS_PAGEFILE_QUOTA_EXCEEDED          ((NTSTATUS)0xC000012C)
#define STATUS_COMMITMENT_LIMIT                 ((NTSTATUS)0xC000012D)
#define STATUS_INVALID_IMAGE_LE_FORMAT          ((NTSTATUS)0xC000012E)
#define STATUS_INVALID_IMAGE_NOT_MZ             ((NTSTATUS)0xC000012F)
#define STATUS_INVALID_IMAGE_PROTECT            ((NTSTATUS)0xC0000130)
#define STATUS_INVALID_IMAGE_WIN_16             ((NTSTATUS)0xC0000131)
#define STATUS_LOGON_SERVER_CONFLICT            ((NTSTATUS)0xC0000132)
#define STATUS_TIME_DIFFERENCE_AT_DC            ((NTSTATUS)0xC0000133)
#define STATUS_SYNCHRONIZATION_REQUIRED         ((NTSTATUS)0xC0000134)
#define STATUS_DLL_NOT_FOUND                    ((NTSTATUS)0xC0000135)
#define STATUS_OPEN_FAILED                      ((NTSTATUS)0xC0000136)
#define STATUS_IO_PRIVILEGE_FAILED              ((NTSTATUS)0xC0000137)
#define STATUS_ORDINAL_NOT_FOUND                ((NTSTATUS)0xC0000138)
#define STATUS_ENTRYPOINT_NOT_FOUND             ((NTSTATUS)0xC0000139)
#define STATUS_CONTROL_C_EXIT                   ((NTSTATUS)0xC000013A)
#define STATUS_LOCAL_DISCONNECT                 ((NTSTATUS)0xC000013B)
#define STATUS_REMOTE_DISCONNECT                ((NTSTATUS)0xC000013C)
#define STATUS_REMOTE_RESOURCES                 ((NTSTATUS)0xC000013D)
#define STATUS_LINK_FAILED                      ((NTSTATUS)0xC000013E)
#define STATUS_LINK_TIMEOUT                     ((NTSTATUS)0xC000013F)
#define STATUS_INVALID_CONNECTION               ((NTSTATUS)0xC0000140)
#define STATUS_INVALID_ADDRESS                  ((NTSTATUS)0xC0000141)
#define STATUS_DLL_INIT_FAILED                  ((NTSTATUS)0xC0000142)
#define STATUS_MISSING_SYSTEMFILE               ((NTSTATUS)0xC0000143)
#define STATUS_UNHANDLED_EXCEPTION              ((NTSTATUS)0xC0000144)
#define STATUS_APP_INIT_FAILURE                 ((NTSTATUS)0xC0000145)
#define STATUS_PAGEFILE_CREATE_FAILED           ((NTSTATUS)0xC0000146)
#define STATUS_NO_PAGEFILE                      ((NTSTATUS)0xC0000147)
#define STATUS_INVALID_LEVEL                    ((NTSTATUS)0xC0000148)
#define STATUS_WRONG_PASSWORD_CORE              ((NTSTATUS)0xC0000149)
#define STATUS_ILLEGAL_FLOAT_CONTEXT            ((NTSTATUS)0xC000014A)
#define STATUS_PIPE_BROKEN                      ((NTSTATUS)0xC000014B)
#define STATUS_REGISTRY_CORRUPT                 ((NTSTATUS)0xC000014C)
#define STATUS_REGISTRY_IO_FAILED               ((NTSTATUS)0xC000014D)
#define STATUS_NO_EVENT_PAIR                    ((NTSTATUS)0xC000014E)
#define STATUS_UNRECOGNIZED_VOLUME              ((NTSTATUS)0xC000014F)
#define STATUS_SERIAL_NO_DEVICE_INITED          ((NTSTATUS)0xC0000150)
#define STATUS_NO_SUCH_ALIAS                    ((NTSTATUS)0xC0000151)
#define STATUS_MEMBER_NOT_IN_ALIAS              ((NTSTATUS)0xC0000152)
#define STATUS_MEMBER_IN_ALIAS                  ((NTSTATUS)0xC0000153)
#define STATUS_ALIAS_EXISTS                     ((NTSTATUS)0xC0000154)
#define STATUS_LOGON_NOT_GRANTED                ((NTSTATUS)0xC0000155)
#define STATUS_TOO_MANY_SECRETS                 ((NTSTATUS)0xC0000156)
#define STATUS_SECRET_TOO_LONG                  ((NTSTATUS)0xC0000157)
#define STATUS_INTERNAL_DB_ERROR                ((NTSTATUS)0xC0000158)
#define STATUS_FULLSCREEN_MODE                  ((NTSTATUS)0xC0000159)
#define STATUS_TOO_MANY_CONTEXT_IDS             ((NTSTATUS)0xC000015A)
#define STATUS_LOGON_TYPE_NOT_GRANTED           ((NTSTATUS)0xC000015B)
#define STATUS_NOT_REGISTRY_FILE                ((NTSTATUS)0xC000015C)
#define STATUS_NT_CROSS_ENCRYPTION_REQUIRED     ((NTSTATUS)0xC000015D)
#define STATUS_DOMAIN_CTRLR_CONFIG_ERROR        ((NTSTATUS)0xC000015E)
#define STATUS_FT_MISSING_MEMBER                ((NTSTATUS)0xC000015F)
#define STATUS_ILL_FORMED_SERVICE_ENTRY         ((NTSTATUS)0xC0000160)
#define STATUS_ILLEGAL_CHARACTER                ((NTSTATUS)0xC0000161)
#define STATUS_UNMAPPABLE_CHARACTER             ((NTSTATUS)0xC0000162)
#define STATUS_UNDEFINED_CHARACTER              ((NTSTATUS)0xC0000163)
#define STATUS_FLOPPY_VOLUME                    ((NTSTATUS)0xC0000164)
#define STATUS_FLOPPY_ID_MARK_NOT_FOUND         ((NTSTATUS)0xC0000165)
#define STATUS_FLOPPY_WRONG_CYLINDER            ((NTSTATUS)0xC0000166)
#define STATUS_FLOPPY_UNKNOWN_ERROR             ((NTSTATUS)0xC0000167)
#define STATUS_FLOPPY_BAD_REGISTERS             ((NTSTATUS)0xC0000168)
#define STATUS_DISK_RECALIBRATE_FAILED          ((NTSTATUS)0xC0000169)
#define STATUS_DISK_OPERATION_FAILED            ((NTSTATUS)0xC000016A)
#define STATUS_DISK_RESET_FAILED                ((NTSTATUS)0xC000016B)
#define STATUS_SHARED_IRQ_BUSY                  ((NTSTATUS)0xC000016C)
#define STATUS_FT_ORPHANING                     ((NTSTATUS)0xC000016D)
#define STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT ((NTSTATUS)0xC000016E)

#define STATUS_PARTITION_FAILURE                ((NTSTATUS)0xC0000172)
#define STATUS_INVALID_BLOCK_LENGTH             ((NTSTATUS)0xC0000173)
#define STATUS_DEVICE_NOT_PARTITIONED           ((NTSTATUS)0xC0000174)
#define STATUS_UNABLE_TO_LOCK_MEDIA             ((NTSTATUS)0xC0000175)
#define STATUS_UNABLE_TO_UNLOAD_MEDIA           ((NTSTATUS)0xC0000176)
#define STATUS_EOM_OVERFLOW                     ((NTSTATUS)0xC0000177)
#define STATUS_NO_MEDIA                         ((NTSTATUS)0xC0000178)
#define STATUS_NO_SUCH_MEMBER                   ((NTSTATUS)0xC000017A)
#define STATUS_INVALID_MEMBER                   ((NTSTATUS)0xC000017B)
#define STATUS_KEY_DELETED                      ((NTSTATUS)0xC000017C)
#define STATUS_NO_LOG_SPACE                     ((NTSTATUS)0xC000017D)
#define STATUS_TOO_MANY_SIDS                    ((NTSTATUS)0xC000017E)
#define STATUS_LM_CROSS_ENCRYPTION_REQUIRED     ((NTSTATUS)0xC000017F)
#define STATUS_KEY_HAS_CHILDREN                 ((NTSTATUS)0xC0000180)
#define STATUS_CHILD_MUST_BE_VOLATILE           ((NTSTATUS)0xC0000181)
#define STATUS_DEVICE_CONFIGURATION_ERROR       ((NTSTATUS)0xC0000182)
#define STATUS_DRIVER_INTERNAL_ERROR            ((NTSTATUS)0xC0000183)
#define STATUS_INVALID_DEVICE_STATE             ((NTSTATUS)0xC0000184)
#define STATUS_IO_DEVICE_ERROR                  ((NTSTATUS)0xC0000185)
#define STATUS_DEVICE_PROTOCOL_ERROR            ((NTSTATUS)0xC0000186)
#define STATUS_BACKUP_CONTROLLER                ((NTSTATUS)0xC0000187)
#define STATUS_LOG_FILE_FULL                    ((NTSTATUS)0xC0000188)
#define STATUS_TOO_LATE                         ((NTSTATUS)0xC0000189)
#define STATUS_NO_TRUST_LSA_SECRET              ((NTSTATUS)0xC000018A)
#define STATUS_NO_TRUST_SAM_ACCOUNT             ((NTSTATUS)0xC000018B)
#define STATUS_TRUSTED_DOMAIN_FAILURE           ((NTSTATUS)0xC000018C)
#define STATUS_TRUSTED_RELATIONSHIP_FAILURE     ((NTSTATUS)0xC000018D)
#define STATUS_EVENTLOG_FILE_CORRUPT            ((NTSTATUS)0xC000018E)
#define STATUS_EVENTLOG_CANT_START              ((NTSTATUS)0xC000018F)
#define STATUS_TRUST_FAILURE                    ((NTSTATUS)0xC0000190)
#define STATUS_MUTANT_LIMIT_EXCEEDED            ((NTSTATUS)0xC0000191)
#define STATUS_NETLOGON_NOT_STARTED             ((NTSTATUS)0xC0000192)
#define STATUS_ACCOUNT_EXPIRED                  ((NTSTATUS)0xC0000193)
#define STATUS_POSSIBLE_DEADLOCK                ((NTSTATUS)0xC0000194)
#define STATUS_NETWORK_CREDENTIAL_CONFLICT      ((NTSTATUS)0xC0000195)
#define STATUS_REMOTE_SESSION_LIMIT             ((NTSTATUS)0xC0000196)
#define STATUS_EVENTLOG_FILE_CHANGED            ((NTSTATUS)0xC0000197)
#define STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT ((NTSTATUS)0xC0000198)
#define STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT ((NTSTATUS)0xC0000199)
#define STATUS_NOLOGON_SERVER_TRUST_ACCOUNT     ((NTSTATUS)0xC000019A)
#define STATUS_DOMAIN_TRUST_INCONSISTENT        ((NTSTATUS)0xC000019B)
#define STATUS_FS_DRIVER_REQUIRED               ((NTSTATUS)0xC000019C)
#define STATUS_NO_USER_SESSION_KEY              ((NTSTATUS)0xC0000202)
#define STATUS_USER_SESSION_DELETED             ((NTSTATUS)0xC0000203)
#define STATUS_RESOURCE_LANG_NOT_FOUND          ((NTSTATUS)0xC0000204)
#define STATUS_INSUFF_SERVER_RESOURCES          ((NTSTATUS)0xC0000205)
#define STATUS_INVALID_BUFFER_SIZE              ((NTSTATUS)0xC0000206)
#define STATUS_INVALID_ADDRESS_COMPONENT        ((NTSTATUS)0xC0000207)
#define STATUS_INVALID_ADDRESS_WILDCARD         ((NTSTATUS)0xC0000208)
#define STATUS_TOO_MANY_ADDRESSES               ((NTSTATUS)0xC0000209)
#define STATUS_ADDRESS_ALREADY_EXISTS           ((NTSTATUS)0xC000020A)
#define STATUS_ADDRESS_CLOSED                   ((NTSTATUS)0xC000020B)
#define STATUS_CONNECTION_DISCONNECTED          ((NTSTATUS)0xC000020C)
#define STATUS_CONNECTION_RESET                 ((NTSTATUS)0xC000020D)
#define STATUS_TOO_MANY_NODES                   ((NTSTATUS)0xC000020E)
#define STATUS_TRANSACTION_ABORTED              ((NTSTATUS)0xC000020F)
#define STATUS_TRANSACTION_TIMED_OUT            ((NTSTATUS)0xC0000210)
#define STATUS_TRANSACTION_NO_RELEASE           ((NTSTATUS)0xC0000211)
#define STATUS_TRANSACTION_NO_MATCH             ((NTSTATUS)0xC0000212)
#define STATUS_TRANSACTION_RESPONDED            ((NTSTATUS)0xC0000213)
#define STATUS_TRANSACTION_INVALID_ID           ((NTSTATUS)0xC0000214)
#define STATUS_TRANSACTION_INVALID_TYPE         ((NTSTATUS)0xC0000215)
#define STATUS_NOT_SERVER_SESSION               ((NTSTATUS)0xC0000216)
#define STATUS_NOT_CLIENT_SESSION               ((NTSTATUS)0xC0000217)
#define STATUS_CANNOT_LOAD_REGISTRY_FILE        ((NTSTATUS)0xC0000218)
#define STATUS_DEBUG_ATTACH_FAILED              ((NTSTATUS)0xC0000219)
#define STATUS_SYSTEM_PROCESS_TERMINATED        ((NTSTATUS)0xC000021A)
#define STATUS_DATA_NOT_ACCEPTED                ((NTSTATUS)0xC000021B)
#define STATUS_NO_BROWSER_SERVERS_FOUND         ((NTSTATUS)0xC000021C)
#define STATUS_VDM_HARD_ERROR                   ((NTSTATUS)0xC000021D)
#define STATUS_DRIVER_CANCEL_TIMEOUT            ((NTSTATUS)0xC000021E)
#define STATUS_REPLY_MESSAGE_MISMATCH           ((NTSTATUS)0xC000021F)
#define STATUS_MAPPED_ALIGNMENT                 ((NTSTATUS)0xC0000220)
#define STATUS_IMAGE_CHECKSUM_MISMATCH          ((NTSTATUS)0xC0000221)
#define STATUS_LOST_WRITEBEHIND_DATA            ((NTSTATUS)0xC0000222)
#define STATUS_CLIENT_SERVER_PARAMETERS_INVALID ((NTSTATUS)0xC0000223)
#define STATUS_PASSWORD_MUST_CHANGE             ((NTSTATUS)0xC0000224)
#define STATUS_NOT_FOUND                        ((NTSTATUS)0xC0000225)
#define STATUS_NOT_TINY_STREAM                  ((NTSTATUS)0xC0000226)
#define STATUS_RECOVERY_FAILURE                 ((NTSTATUS)0xC0000227)
#define STATUS_STACK_OVERFLOW_READ              ((NTSTATUS)0xC0000228)
#define STATUS_FAIL_CHECK                       ((NTSTATUS)0xC0000229)
#define STATUS_DUPLICATE_OBJECTID               ((NTSTATUS)0xC000022A)
#define STATUS_OBJECTID_EXISTS                  ((NTSTATUS)0xC000022B)
#define STATUS_CONVERT_TO_LARGE                 ((NTSTATUS)0xC000022C)
#define STATUS_RETRY                            ((NTSTATUS)0xC000022D)
#define STATUS_FOUND_OUT_OF_SCOPE               ((NTSTATUS)0xC000022E)
#define STATUS_ALLOCATE_BUCKET                  ((NTSTATUS)0xC000022F)
#define STATUS_PROPSET_NOT_FOUND                ((NTSTATUS)0xC0000230)
#define STATUS_MARSHALL_OVERFLOW                ((NTSTATUS)0xC0000231)
#define STATUS_INVALID_VARIANT                  ((NTSTATUS)0xC0000232)
#define STATUS_DOMAIN_CONTROLLER_NOT_FOUND      ((NTSTATUS)0xC0000233)
#define STATUS_ACCOUNT_LOCKED_OUT               ((NTSTATUS)0xC0000234)
#define STATUS_HANDLE_NOT_CLOSABLE              ((NTSTATUS)0xC0000235)
#define STATUS_CONNECTION_REFUSED               ((NTSTATUS)0xC0000236)
#define STATUS_GRACEFUL_DISCONNECT              ((NTSTATUS)0xC0000237)
#define STATUS_ADDRESS_ALREADY_ASSOCIATED       ((NTSTATUS)0xC0000238)
#define STATUS_ADDRESS_NOT_ASSOCIATED           ((NTSTATUS)0xC0000239)
#define STATUS_CONNECTION_INVALID               ((NTSTATUS)0xC000023A)
#define STATUS_CONNECTION_ACTIVE                ((NTSTATUS)0xC000023B)
#define STATUS_NETWORK_UNREACHABLE              ((NTSTATUS)0xC000023C)
#define STATUS_HOST_UNREACHABLE                 ((NTSTATUS)0xC000023D)
#define STATUS_PROTOCOL_UNREACHABLE             ((NTSTATUS)0xC000023E)
#define STATUS_PORT_UNREACHABLE                 ((NTSTATUS)0xC000023F)
#define STATUS_REQUEST_ABORTED                  ((NTSTATUS)0xC0000240)
#define STATUS_CONNECTION_ABORTED               ((NTSTATUS)0xC0000241)
#define STATUS_BAD_COMPRESSION_BUFFER           ((NTSTATUS)0xC0000242)
#define STATUS_USER_MAPPED_FILE                 ((NTSTATUS)0xC0000243)
#define STATUS_AUDIT_FAILED                     ((NTSTATUS)0xC0000244)
#define STATUS_TIMER_RESOLUTION_NOT_SET         ((NTSTATUS)0xC0000245)
#define STATUS_CONNECTION_COUNT_LIMIT           ((NTSTATUS)0xC0000246)
#define STATUS_LOGIN_TIME_RESTRICTION           ((NTSTATUS)0xC0000247)
#define STATUS_LOGIN_WKSTA_RESTRICTION          ((NTSTATUS)0xC0000248)
#define STATUS_IMAGE_MP_UP_MISMATCH             ((NTSTATUS)0xC0000249)
#define STATUS_INSUFFICIENT_LOGON_INFO          ((NTSTATUS)0xC0000250)
#define STATUS_BAD_DLL_ENTRYPOINT               ((NTSTATUS)0xC0000251)
#define STATUS_BAD_SERVICE_ENTRYPOINT           ((NTSTATUS)0xC0000252)
#define STATUS_LPC_REPLY_LOST                   ((NTSTATUS)0xC0000253)
#define STATUS_IP_ADDRESS_CONFLICT1             ((NTSTATUS)0xC0000254)
#define STATUS_IP_ADDRESS_CONFLICT2             ((NTSTATUS)0xC0000255)
#define STATUS_REGISTRY_QUOTA_LIMIT             ((NTSTATUS)0xC0000256)
#define STATUS_PATH_NOT_COVERED                 ((NTSTATUS)0xC0000257)
#define STATUS_NO_CALLBACK_ACTIVE               ((NTSTATUS)0xC0000258)
#define STATUS_LICENSE_QUOTA_EXCEEDED           ((NTSTATUS)0xC0000259)
#define STATUS_PWD_TOO_SHORT                    ((NTSTATUS)0xC000025A)
#define STATUS_PWD_TOO_RECENT                   ((NTSTATUS)0xC000025B)
#define STATUS_PWD_HISTORY_CONFLICT             ((NTSTATUS)0xC000025C)
#define STATUS_PLUGPLAY_NO_DEVICE               ((NTSTATUS)0xC000025E)
#define STATUS_UNSUPPORTED_COMPRESSION          ((NTSTATUS)0xC000025F)
#define STATUS_INVALID_HW_PROFILE               ((NTSTATUS)0xC0000260)
#define STATUS_INVALID_PLUGPLAY_DEVICE_PATH     ((NTSTATUS)0xC0000261)
#define STATUS_DRIVER_ORDINAL_NOT_FOUND         ((NTSTATUS)0xC0000262)
#define STATUS_DRIVER_ENTRYPOINT_NOT_FOUND      ((NTSTATUS)0xC0000263)
#define STATUS_RESOURCE_NOT_OWNED               ((NTSTATUS)0xC0000264)
#define STATUS_TOO_MANY_LINKS                   ((NTSTATUS)0xC0000265)
#define STATUS_QUOTA_LIST_INCONSISTENT          ((NTSTATUS)0xC0000266)
#define STATUS_FILE_IS_OFFLINE                  ((NTSTATUS)0xC0000267)
#define STATUS_EVALUATION_EXPIRATION            ((NTSTATUS)0xC0000268)
#define STATUS_ILLEGAL_DLL_RELOCATION           ((NTSTATUS)0xC0000269)
#define STATUS_LICENSE_VIOLATION                ((NTSTATUS)0xC000026A)
#define STATUS_DLL_INIT_FAILED_LOGOFF           ((NTSTATUS)0xC000026B)
#define STATUS_DRIVER_UNABLE_TO_LOAD            ((NTSTATUS)0xC000026C)
#define STATUS_DFS_UNAVAILABLE                  ((NTSTATUS)0xC000026D)
#define STATUS_VOLUME_DISMOUNTED                ((NTSTATUS)0xC000026E)
#define STATUS_WX86_INTERNAL_ERROR              ((NTSTATUS)0xC000026F)
#define STATUS_WX86_FLOAT_STACK_CHECK           ((NTSTATUS)0xC0000270)
#define STATUS_VALIDATE_CONTINUE                ((NTSTATUS)0xC0000271)
#define STATUS_NO_MATCH                         ((NTSTATUS)0xC0000272)
#define STATUS_NO_MORE_MATCHES                  ((NTSTATUS)0xC0000273)
#define STATUS_NOT_A_REPARSE_POINT              ((NTSTATUS)0xC0000275)
#define STATUS_IO_REPARSE_TAG_INVALID           ((NTSTATUS)0xC0000276)
#define STATUS_IO_REPARSE_TAG_MISMATCH          ((NTSTATUS)0xC0000277)
#define STATUS_IO_REPARSE_DATA_INVALID          ((NTSTATUS)0xC0000278)
#define STATUS_IO_REPARSE_TAG_NOT_HANDLED       ((NTSTATUS)0xC0000279)
#define STATUS_REPARSE_POINT_NOT_RESOLVED       ((NTSTATUS)0xC0000280)
#define STATUS_DIRECTORY_IS_A_REPARSE_POINT     ((NTSTATUS)0xC0000281)
#define STATUS_RANGE_LIST_CONFLICT              ((NTSTATUS)0xC0000282)
#define STATUS_SOURCE_ELEMENT_EMPTY             ((NTSTATUS)0xC0000283)
#define STATUS_DESTINATION_ELEMENT_FULL         ((NTSTATUS)0xC0000284)
#define STATUS_ILLEGAL_ELEMENT_ADDRESS          ((NTSTATUS)0xC0000285)
#define STATUS_MAGAZINE_NOT_PRESENT             ((NTSTATUS)0xC0000286)
#define STATUS_REINITIALIZATION_NEEDED          ((NTSTATUS)0xC0000287)
#define STATUS_ENCRYPTION_FAILED                ((NTSTATUS)0xC000028A)
#define STATUS_DECRYPTION_FAILED                ((NTSTATUS)0xC000028B)
#define STATUS_RANGE_NOT_FOUND                  ((NTSTATUS)0xC000028C)
#define STATUS_NO_RECOVERY_POLICY               ((NTSTATUS)0xC000028D)
#define STATUS_NO_EFS                           ((NTSTATUS)0xC000028E)
#define STATUS_WRONG_EFS                        ((NTSTATUS)0xC000028F)
#define STATUS_NO_USER_KEYS                     ((NTSTATUS)0xC0000290)
#define STATUS_FILE_NOT_ENCRYPTED               ((NTSTATUS)0xC0000291)
#define STATUS_NOT_EXPORT_FORMAT                ((NTSTATUS)0xC0000292)
#define STATUS_FILE_ENCRYPTED                   ((NTSTATUS)0xC0000293)
#define STATUS_WMI_GUID_NOT_FOUND               ((NTSTATUS)0xC0000295)
#define STATUS_WMI_INSTANCE_NOT_FOUND           ((NTSTATUS)0xC0000296)
#define STATUS_WMI_ITEMID_NOT_FOUND             ((NTSTATUS)0xC0000297)
#define STATUS_WMI_TRY_AGAIN                    ((NTSTATUS)0xC0000298)
#define STATUS_SHARED_POLICY                    ((NTSTATUS)0xC0000299)
#define STATUS_POLICY_OBJECT_NOT_FOUND          ((NTSTATUS)0xC000029A)
#define STATUS_POLICY_ONLY_IN_DS                ((NTSTATUS)0xC000029B)
#define STATUS_VOLUME_NOT_UPGRADED              ((NTSTATUS)0xC000029C)
#define STATUS_REMOTE_STORAGE_NOT_ACTIVE        ((NTSTATUS)0xC000029D)
#define STATUS_REMOTE_STORAGE_MEDIA_ERROR       ((NTSTATUS)0xC000029E)
#define STATUS_NO_TRACKING_SERVICE              ((NTSTATUS)0xC000029F)
#define STATUS_SERVER_SID_MISMATCH              ((NTSTATUS)0xC00002A0)
#define STATUS_DS_NO_ATTRIBUTE_OR_VALUE         ((NTSTATUS)0xC00002A1)
#define STATUS_DS_INVALID_ATTRIBUTE_SYNTAX      ((NTSTATUS)0xC00002A2)
#define STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED      ((NTSTATUS)0xC00002A3)
#define STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS     ((NTSTATUS)0xC00002A4)
#define STATUS_DS_BUSY                          ((NTSTATUS)0xC00002A5)
#define STATUS_DS_UNAVAILABLE                   ((NTSTATUS)0xC00002A6)
#define STATUS_DS_NO_RIDS_ALLOCATED             ((NTSTATUS)0xC00002A7)
#define STATUS_DS_NO_MORE_RIDS                  ((NTSTATUS)0xC00002A8)
#define STATUS_DS_INCORRECT_ROLE_OWNER          ((NTSTATUS)0xC00002A9)
#define STATUS_DS_RIDMGR_INIT_ERROR             ((NTSTATUS)0xC00002AA)
#define STATUS_DS_OBJ_CLASS_VIOLATION           ((NTSTATUS)0xC00002AB)
#define STATUS_DS_CANT_ON_NON_LEAF              ((NTSTATUS)0xC00002AC)
#define STATUS_DS_CANT_ON_RDN                   ((NTSTATUS)0xC00002AD)
#define STATUS_DS_CANT_MOD_OBJ_CLASS            ((NTSTATUS)0xC00002AE)
#define STATUS_DS_CROSS_DOM_MOVE_FAILED         ((NTSTATUS)0xC00002AF)
#define STATUS_DS_GC_NOT_AVAILABLE              ((NTSTATUS)0xC00002B0)
#define STATUS_DIRECTORY_SERVICE_REQUIRED       ((NTSTATUS)0xC00002B1)
#define STATUS_REPARSE_ATTRIBUTE_CONFLICT       ((NTSTATUS)0xC00002B2)
#define STATUS_CANT_ENABLE_DENY_ONLY            ((NTSTATUS)0xC00002B3)
#define STATUS_FLOAT_MULTIPLE_FAULTS            ((NTSTATUS)0xC00002B4)
#define STATUS_FLOAT_MULTIPLE_TRAPS             ((NTSTATUS)0xC00002B5)
#define STATUS_DEVICE_REMOVED                   ((NTSTATUS)0xC00002B6)
#define STATUS_JOURNAL_DELETE_IN_PROGRESS       ((NTSTATUS)0xC00002B7)
#define STATUS_JOURNAL_NOT_ACTIVE               ((NTSTATUS)0xC00002B8)
#define STATUS_NOINTERFACE                      ((NTSTATUS)0xC00002B9)
#define STATUS_DS_ADMIN_LIMIT_EXCEEDED          ((NTSTATUS)0xC00002C1)
#define STATUS_DRIVER_FAILED_SLEEP              ((NTSTATUS)0xC00002C2)
#define STATUS_MUTUAL_AUTHENTICATION_FAILED     ((NTSTATUS)0xC00002C3)
#define STATUS_CORRUPT_SYSTEM_FILE              ((NTSTATUS)0xC00002C4)
#define STATUS_DATATYPE_MISALIGNMENT_ERROR      ((NTSTATUS)0xC00002C5)
#define STATUS_WMI_READ_ONLY                    ((NTSTATUS)0xC00002C6)
#define STATUS_WMI_SET_FAILURE                  ((NTSTATUS)0xC00002C7)
#define STATUS_COMMITMENT_MINIMUM               ((NTSTATUS)0xC00002C8)
#define STATUS_REG_NAT_CONSUMPTION              ((NTSTATUS)0xC00002C9)
#define STATUS_TRANSPORT_FULL                   ((NTSTATUS)0xC00002CA)
#define STATUS_DS_SAM_INIT_FAILURE              ((NTSTATUS)0xC00002CB)
#define STATUS_ONLY_IF_CONNECTED                ((NTSTATUS)0xC00002CC)
#define STATUS_DS_SENSITIVE_GROUP_VIOLATION     ((NTSTATUS)0xC00002CD)
#define STATUS_PNP_RESTART_ENUMERATION          ((NTSTATUS)0xC00002CE)
#define STATUS_JOURNAL_ENTRY_DELETED            ((NTSTATUS)0xC00002CF)
#define STATUS_DS_CANT_MOD_PRIMARYGROUPID       ((NTSTATUS)0xC00002D0)
#define STATUS_SYSTEM_IMAGE_BAD_SIGNATURE       ((NTSTATUS)0xC00002D1)
#define STATUS_PNP_REBOOT_REQUIRED              ((NTSTATUS)0xC00002D2)
#define STATUS_POWER_STATE_INVALID              ((NTSTATUS)0xC00002D3)
#define STATUS_DS_INVALID_GROUP_TYPE                            ((NTSTATUS)0xC00002D4)
#define STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN            ((NTSTATUS)0xC00002D5)
#define STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN             ((NTSTATUS)0xC00002D6)
#define STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER                 ((NTSTATUS)0xC00002D7)
#define STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER             ((NTSTATUS)0xC00002D8)
#define STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER              ((NTSTATUS)0xC00002D9)
#define STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER           ((NTSTATUS)0xC00002DA)
#define STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER      ((NTSTATUS)0xC00002DB)
#define STATUS_DS_HAVE_PRIMARY_MEMBERS                          ((NTSTATUS)0xC00002DC)
#define STATUS_WMI_NOT_SUPPORTED                        ((NTSTATUS)0xC00002DD)
#define STATUS_INSUFFICIENT_POWER                       ((NTSTATUS)0xC00002DE)
#define STATUS_SAM_NEED_BOOTKEY_PASSWORD                ((NTSTATUS)0xC00002DF)
#define STATUS_SAM_NEED_BOOTKEY_FLOPPY                  ((NTSTATUS)0xC00002E0)
#define STATUS_DS_CANT_START                            ((NTSTATUS)0xC00002E1)
#define STATUS_DS_INIT_FAILURE                          ((NTSTATUS)0xC00002E2)
#define STATUS_SAM_INIT_FAILURE                         ((NTSTATUS)0xC00002E3)
#define STATUS_DS_GC_REQUIRED                           ((NTSTATUS)0xC00002E4)
#define STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY            ((NTSTATUS)0xC00002E5)
#define STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS            ((NTSTATUS)0xC00002E6)
#define STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED        ((NTSTATUS)0xC00002E7)
#define STATUS_MULTIPLE_FAULT_VIOLATION         ((NTSTATUS)0xC00002E8)
#define STATUS_CURRENT_DOMAIN_NOT_ALLOWED       ((NTSTATUS)0xC00002E9)
#define STATUS_CANNOT_MAKE                      ((NTSTATUS)0xC00002EA)
#define STATUS_SYSTEM_SHUTDOWN                  ((NTSTATUS)0xC00002EB)
#define STATUS_DS_INIT_FAILURE_CONSOLE          ((NTSTATUS)0xC00002EC)
#define STATUS_DS_SAM_INIT_FAILURE_CONSOLE      ((NTSTATUS)0xC00002ED)
#define STATUS_UNFINISHED_CONTEXT_DELETED       ((NTSTATUS)0xC00002EE)
#define STATUS_NO_TGT_REPLY                     ((NTSTATUS)0xC00002EF)
#define STATUS_OBJECTID_NOT_FOUND               ((NTSTATUS)0xC00002F0)
#define STATUS_NO_IP_ADDRESSES                  ((NTSTATUS)0xC00002F1)
#define STATUS_WRONG_CREDENTIAL_HANDLE          ((NTSTATUS)0xC00002F2)
#define STATUS_CRYPTO_SYSTEM_INVALID            ((NTSTATUS)0xC00002F3)
#define STATUS_MAX_REFERRALS_EXCEEDED           ((NTSTATUS)0xC00002F4)
#define STATUS_MUST_BE_KDC                      ((NTSTATUS)0xC00002F5)
#define STATUS_STRONG_CRYPTO_NOT_SUPPORTED      ((NTSTATUS)0xC00002F6)
#define STATUS_TOO_MANY_PRINCIPALS              ((NTSTATUS)0xC00002F7)
#define STATUS_NO_PA_DATA                       ((NTSTATUS)0xC00002F8)
#define STATUS_PKINIT_NAME_MISMATCH             ((NTSTATUS)0xC00002F9)
#define STATUS_SMARTCARD_LOGON_REQUIRED         ((NTSTATUS)0xC00002FA)
#define STATUS_KDC_INVALID_REQUEST              ((NTSTATUS)0xC00002FB)
#define STATUS_KDC_UNABLE_TO_REFER              ((NTSTATUS)0xC00002FC)
#define STATUS_KDC_UNKNOWN_ETYPE                ((NTSTATUS)0xC00002FD)
#define STATUS_SHUTDOWN_IN_PROGRESS             ((NTSTATUS)0xC00002FE)
#define STATUS_SERVER_SHUTDOWN_IN_PROGRESS      ((NTSTATUS)0xC00002FF)
#define STATUS_NOT_SUPPORTED_ON_SBS             ((NTSTATUS)0xC0000300)
#define STATUS_WMI_GUID_DISCONNECTED            ((NTSTATUS)0xC0000301)
#define STATUS_WMI_ALREADY_DISABLED             ((NTSTATUS)0xC0000302)
#define STATUS_WMI_ALREADY_ENABLED              ((NTSTATUS)0xC0000303)
#define STATUS_MFT_TOO_FRAGMENTED               ((NTSTATUS)0xC0000304)
#define STATUS_COPY_PROTECTION_FAILURE          ((NTSTATUS)0xC0000305)
#define STATUS_CSS_AUTHENTICATION_FAILURE       ((NTSTATUS)0xC0000306)
#define STATUS_CSS_KEY_NOT_PRESENT              ((NTSTATUS)0xC0000307)
#define STATUS_CSS_KEY_NOT_ESTABLISHED          ((NTSTATUS)0xC0000308)
#define STATUS_CSS_SCRAMBLED_SECTOR             ((NTSTATUS)0xC0000309)
#define STATUS_CSS_REGION_MISMATCH              ((NTSTATUS)0xC000030A)
#define STATUS_CSS_RESETS_EXHAUSTED             ((NTSTATUS)0xC000030B)
#define STATUS_PKINIT_FAILURE                   ((NTSTATUS)0xC0000320)
#define STATUS_SMARTCARD_SUBSYSTEM_FAILURE      ((NTSTATUS)0xC0000321)
#define STATUS_NO_KERB_KEY                      ((NTSTATUS)0xC0000322)
#define STATUS_HOST_DOWN                        ((NTSTATUS)0xC0000350)
#define STATUS_UNSUPPORTED_PREAUTH              ((NTSTATUS)0xC0000351)
#define STATUS_EFS_ALG_BLOB_TOO_BIG             ((NTSTATUS)0xC0000352)
#define STATUS_PORT_NOT_SET                     ((NTSTATUS)0xC0000353)
#define STATUS_DEBUGGER_INACTIVE                ((NTSTATUS)0xC0000354)
#define STATUS_DS_VERSION_CHECK_FAILURE         ((NTSTATUS)0xC0000355)
#define STATUS_AUDITING_DISABLED                ((NTSTATUS)0xC0000356)
#define STATUS_PRENT4_MACHINE_ACCOUNT           ((NTSTATUS)0xC0000357)
#define STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER ((NTSTATUS)0xC0000358)
#define STATUS_INVALID_IMAGE_WIN_32             ((NTSTATUS)0xC0000359)
#define STATUS_INVALID_IMAGE_WIN_64             ((NTSTATUS)0xC000035A)
#define STATUS_BAD_BINDINGS                     ((NTSTATUS)0xC000035B)
#define STATUS_NETWORK_SESSION_EXPIRED          ((NTSTATUS)0xC000035C)
#define STATUS_APPHELP_BLOCK                    ((NTSTATUS)0xC000035D)
#define STATUS_ALL_SIDS_FILTERED                ((NTSTATUS)0xC000035E)
#define STATUS_NOT_SAFE_MODE_DRIVER             ((NTSTATUS)0xC000035F)
#define STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT        ((NTSTATUS)0xC0000361)
#define STATUS_ACCESS_DISABLED_BY_POLICY_PATH           ((NTSTATUS)0xC0000362)
#define STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER      ((NTSTATUS)0xC0000363)
#define STATUS_ACCESS_DISABLED_BY_POLICY_OTHER          ((NTSTATUS)0xC0000364)
#define STATUS_FAILED_DRIVER_ENTRY              ((NTSTATUS)0xC0000365)
#define STATUS_DEVICE_ENUMERATION_ERROR         ((NTSTATUS)0xC0000366)
#define STATUS_WAIT_FOR_OPLOCK                  ((NTSTATUS)0x00000367)
#define STATUS_MOUNT_POINT_NOT_RESOLVED         ((NTSTATUS)0xC0000368)
#define STATUS_INVALID_DEVICE_OBJECT_PARAMETER  ((NTSTATUS)0xC0000369)
#define STATUS_MCA_OCCURED                      ((NTSTATUS)0xC000036A)
#define STATUS_DRIVER_BLOCKED_CRITICAL          ((NTSTATUS)0xC000036B)
#define STATUS_DRIVER_BLOCKED                   ((NTSTATUS)0xC000036C)
#define STATUS_DRIVER_DATABASE_ERROR            ((NTSTATUS)0xC000036D)
#define STATUS_SYSTEM_HIVE_TOO_LARGE            ((NTSTATUS)0xC000036E)
#define STATUS_INVALID_IMPORT_OF_NON_DLL        ((NTSTATUS)0xC000036F)
#define STATUS_SMARTCARD_WRONG_PIN              ((NTSTATUS)0xC0000380)
#define STATUS_SMARTCARD_CARD_BLOCKED           ((NTSTATUS)0xC0000381)
#define STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED ((NTSTATUS)0xC0000382)
#define STATUS_SMARTCARD_NO_CARD                ((NTSTATUS)0xC0000383)
#define STATUS_SMARTCARD_NO_KEY_CONTAINER       ((NTSTATUS)0xC0000384)
#define STATUS_SMARTCARD_NO_CERTIFICATE         ((NTSTATUS)0xC0000385)
#define STATUS_SMARTCARD_NO_KEYSET              ((NTSTATUS)0xC0000386)
#define STATUS_SMARTCARD_IO_ERROR               ((NTSTATUS)0xC0000387)
#define STATUS_DOWNGRADE_DETECTED               ((NTSTATUS)0xC0000388)
#define STATUS_SMARTCARD_CERT_REVOKED           ((NTSTATUS)0xC0000389)
#define STATUS_ISSUING_CA_UNTRUSTED             ((NTSTATUS)0xC000038A)
#define STATUS_REVOCATION_OFFLINE_C             ((NTSTATUS)0xC000038B)
#define STATUS_PKINIT_CLIENT_FAILURE            ((NTSTATUS)0xC000038C)
#define STATUS_SMARTCARD_CERT_EXPIRED           ((NTSTATUS)0xC000038D)
#define STATUS_DRIVER_FAILED_PRIOR_UNLOAD       ((NTSTATUS)0xC000038E)
#define STATUS_SMARTCARD_SILENT_CONTEXT         ((NTSTATUS)0xC000038F)
#define STATUS_PER_USER_TRUST_QUOTA_EXCEEDED    ((NTSTATUS)0xC0000401)
#define STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED    ((NTSTATUS)0xC0000402)
#define STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED ((NTSTATUS)0xC0000403)
#define STATUS_DS_NAME_NOT_UNIQUE               ((NTSTATUS)0xC0000404)
#define STATUS_DS_DUPLICATE_ID_FOUND            ((NTSTATUS)0xC0000405)
#define STATUS_DS_GROUP_CONVERSION_ERROR        ((NTSTATUS)0xC0000406)
#define STATUS_VOLSNAP_PREPARE_HIBERNATE        ((NTSTATUS)0xC0000407)
#define STATUS_USER2USER_REQUIRED               ((NTSTATUS)0xC0000408)
#define STATUS_STACK_BUFFER_OVERRUN             ((NTSTATUS)0xC0000409)
#define STATUS_NO_S4U_PROT_SUPPORT              ((NTSTATUS)0xC000040A)
#define STATUS_CROSSREALM_DELEGATION_FAILURE    ((NTSTATUS)0xC000040B)
#define STATUS_REVOCATION_OFFLINE_KDC           ((NTSTATUS)0xC000040C)
#define STATUS_ISSUING_CA_UNTRUSTED_KDC         ((NTSTATUS)0xC000040D)
#define STATUS_KDC_CERT_EXPIRED                 ((NTSTATUS)0xC000040E)
#define STATUS_KDC_CERT_REVOKED                 ((NTSTATUS)0xC000040F)
#define STATUS_PARAMETER_QUOTA_EXCEEDED         ((NTSTATUS)0xC0000410)
#define STATUS_HIBERNATION_FAILURE              ((NTSTATUS)0xC0000411)
#define STATUS_DELAY_LOAD_FAILED                ((NTSTATUS)0xC0000412)
#define STATUS_AUTHENTICATION_FIREWALL_FAILED   ((NTSTATUS)0xC0000413)
#define STATUS_VDM_DISALLOWED                   ((NTSTATUS)0xC0000414)
#define STATUS_HUNG_DISPLAY_DRIVER_THREAD       ((NTSTATUS)0xC0000415)
#define STATUS_INVALID_CRUNTIME_PARAMETER       ((NTSTATUS)0xC0000417)
#define STATUS_ASSERTION_FAILURE                ((NTSTATUS)0xC0000420)
#define STATUS_CALLBACK_POP_STACK               ((NTSTATUS)0xC0000423)
#define STATUS_HIVE_UNLOADED                    ((NTSTATUS)0xC0000425)
#define STATUS_ELEVATION_REQUIRED               ((NTSTATUS)0xC000042C)
#define STATUS_PURGE_FAILED                     ((NTSTATUS)0xC0000435)
#define STATUS_CRED_REQUIRES_CONFIRMATION       ((NTSTATUS)0xC0000440)
#define STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE ((NTSTATUS)0xC0000441)
#define STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER ((NTSTATUS)0xC0000442)
#define STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE ((NTSTATUS)0xC0000443)
#define STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE ((NTSTATUS)0xC0000444)
#define STATUS_CS_ENCRYPTION_FILE_NOT_CSE       ((NTSTATUS)0xC0000445)
#define STATUS_INVALID_LABEL                    ((NTSTATUS)0xC0000446)
#define STATUS_DRIVER_PROCESS_TERMINATED        ((NTSTATUS)0xC0000450)
#define STATUS_AMBIGUOUS_SYSTEM_DEVICE          ((NTSTATUS)0xC0000451)
#define STATUS_SYSTEM_DEVICE_NOT_FOUND          ((NTSTATUS)0xC0000452)
#define STATUS_RESTART_BOOT_APPLICATION         ((NTSTATUS)0xC0000453)
#define STATUS_INSUFFICIENT_NVRAM_RESOURCES     ((NTSTATUS)0xC0000454)
#define STATUS_INVALID_SESSION                  ((NTSTATUS)0xC0000455)
#define STATUS_THREAD_ALREADY_IN_SESSION        ((NTSTATUS)0xC0000456)
#define STATUS_THREAD_NOT_IN_SESSION            ((NTSTATUS)0xC0000457)
#define STATUS_INVALID_WEIGHT                   ((NTSTATUS)0xC0000458)
#define STATUS_REQUEST_PAUSED                   ((NTSTATUS)0xC0000459)
#define STATUS_NO_RANGES_PROCESSED              ((NTSTATUS)0xC0000460)
#define STATUS_DISK_RESOURCES_EXHAUSTED         ((NTSTATUS)0xC0000461)
#define STATUS_NEEDS_REMEDIATION                ((NTSTATUS)0xC0000462)
#define STATUS_DEVICE_FEATURE_NOT_SUPPORTED     ((NTSTATUS)0xC0000463)
#define STATUS_DEVICE_UNREACHABLE               ((NTSTATUS)0xC0000464)
#define STATUS_INVALID_TOKEN                    ((NTSTATUS)0xC0000465)
#define STATUS_SERVER_UNAVAILABLE               ((NTSTATUS)0xC0000466)
#define STATUS_FILE_NOT_AVAILABLE               ((NTSTATUS)0xC0000467)
#define STATUS_DEVICE_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC0000468)
#define STATUS_PACKAGE_UPDATING                 ((NTSTATUS)0xC0000469)
#define STATUS_NOT_READ_FROM_COPY               ((NTSTATUS)0xC000046A)
#define STATUS_FT_WRITE_FAILURE                 ((NTSTATUS)0xC000046B)
#define STATUS_FT_DI_SCAN_REQUIRED              ((NTSTATUS)0xC000046C)
#define STATUS_OBJECT_NOT_EXTERNALLY_BACKED     ((NTSTATUS)0xC000046D)
#define STATUS_EXTERNAL_BACKING_PROVIDER_UNKNOWN ((NTSTATUS)0xC000046E)
#define STATUS_COMPRESSION_NOT_BENEFICIAL       ((NTSTATUS)0xC000046F)
#define STATUS_DATA_CHECKSUM_ERROR              ((NTSTATUS)0xC0000470)
#define STATUS_INTERMIXED_KERNEL_EA_OPERATION   ((NTSTATUS)0xC0000471)
#define STATUS_TRIM_READ_ZERO_NOT_SUPPORTED     ((NTSTATUS)0xC0000472)
#define STATUS_TOO_MANY_SEGMENT_DESCRIPTORS     ((NTSTATUS)0xC0000473)
#define STATUS_INVALID_OFFSET_ALIGNMENT         ((NTSTATUS)0xC0000474)
#define STATUS_INVALID_FIELD_IN_PARAMETER_LIST  ((NTSTATUS)0xC0000475)
#define STATUS_OPERATION_IN_PROGRESS            ((NTSTATUS)0xC0000476)
#define STATUS_INVALID_INITIATOR_TARGET_PATH    ((NTSTATUS)0xC0000477)
#define STATUS_SCRUB_DATA_DISABLED              ((NTSTATUS)0xC0000478)
#define STATUS_NOT_REDUNDANT_STORAGE            ((NTSTATUS)0xC0000479)
#define STATUS_RESIDENT_FILE_NOT_SUPPORTED      ((NTSTATUS)0xC000047A)
#define STATUS_COMPRESSED_FILE_NOT_SUPPORTED    ((NTSTATUS)0xC000047B)
#define STATUS_DIRECTORY_NOT_SUPPORTED          ((NTSTATUS)0xC000047C)
#define STATUS_IO_OPERATION_TIMEOUT             ((NTSTATUS)0xC000047D)
#define STATUS_SYSTEM_NEEDS_REMEDIATION         ((NTSTATUS)0xC000047E)
#define STATUS_APPX_INTEGRITY_FAILURE_CLR_NGEN  ((NTSTATUS)0xC000047F)
#define STATUS_SHARE_UNAVAILABLE                ((NTSTATUS)0xC0000480)
#define STATUS_APISET_NOT_HOSTED                ((NTSTATUS)0xC0000481)
#define STATUS_APISET_NOT_PRESENT               ((NTSTATUS)0xC0000482)
#define STATUS_DEVICE_HARDWARE_ERROR            ((NTSTATUS)0xC0000483)
#define STATUS_FIRMWARE_SLOT_INVALID            ((NTSTATUS)0xC0000484)
#define STATUS_FIRMWARE_IMAGE_INVALID           ((NTSTATUS)0xC0000485)
#define STATUS_STORAGE_TOPOLOGY_ID_MISMATCH     ((NTSTATUS)0xC0000486)
#define STATUS_WIM_NOT_BOOTABLE                 ((NTSTATUS)0xC0000487)
#define STATUS_BLOCKED_BY_PARENTAL_CONTROLS     ((NTSTATUS)0xC0000488)
#define STATUS_NEEDS_REGISTRATION               ((NTSTATUS)0xC0000489)
#define STATUS_QUOTA_ACTIVITY                   ((NTSTATUS)0xC000048A)
#define STATUS_CALLBACK_INVOKE_INLINE           ((NTSTATUS)0xC000048B)
#define STATUS_BLOCK_TOO_MANY_REFERENCES        ((NTSTATUS)0xC000048C)
#define STATUS_MARKED_TO_DISALLOW_WRITES        ((NTSTATUS)0xC000048D)
#define STATUS_NETWORK_ACCESS_DENIED_EDP        ((NTSTATUS)0xC000048E)
#define STATUS_ENCLAVE_FAILURE                  ((NTSTATUS)0xC000048F)
#define STATUS_PNP_NO_COMPAT_DRIVERS            ((NTSTATUS)0xC0000490)
#define STATUS_PNP_DRIVER_PACKAGE_NOT_FOUND     ((NTSTATUS)0xC0000491)
#define STATUS_PNP_DRIVER_CONFIGURATION_NOT_FOUND  ((NTSTATUS)0xC0000492)
#define STATUS_PNP_DRIVER_CONFIGURATION_INCOMPLETE ((NTSTATUS)0xC0000493)
#define STATUS_PNP_FUNCTION_DRIVER_REQUIRED     ((NTSTATUS)0xC0000494)
#define STATUS_PNP_DEVICE_CONFIGURATION_PENDING ((NTSTATUS)0xC0000495)
#define STATUS_DEVICE_HINT_NAME_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000496)
#define STATUS_PACKAGE_NOT_AVAILABLE            ((NTSTATUS)0xC0000497)
#define STATUS_DEVICE_IN_MAINTENANCE            ((NTSTATUS)0xC0000499)
#define STATUS_NOT_SUPPORTED_ON_DAX             ((NTSTATUS)0xC000049A)
#define STATUS_FREE_SPACE_TOO_FRAGMENTED        ((NTSTATUS)0xC000049B)
#define STATUS_DAX_MAPPING_EXISTS               ((NTSTATUS)0xC000049C)
#define STATUS_CHILD_PROCESS_BLOCKED            ((NTSTATUS)0xC000049D)
#define STATUS_STORAGE_LOST_DATA_PERSISTENCE    ((NTSTATUS)0xC000049E)
#define STATUS_VRF_CFG_AND_IO_ENABLED           ((NTSTATUS)0xC000049F)
#define STATUS_PARTITION_TERMINATING            ((NTSTATUS)0xC00004A0)
#define STATUS_EXTERNAL_SYSKEY_NOT_SUPPORTED    ((NTSTATUS)0xC00004A1)
#define STATUS_ENCLAVE_VIOLATION                ((NTSTATUS)0xC00004A2)
#define STATUS_FILE_PROTECTED_UNDER_DPL         ((NTSTATUS)0xC00004A3)
#define STATUS_VOLUME_NOT_CLUSTER_ALIGNED       ((NTSTATUS)0xC00004A4)
#define STATUS_NO_PHYSICALLY_ALIGNED_FREE_SPACE_FOUND ((NTSTATUS)0xC00004A5)
#define STATUS_APPX_FILE_NOT_ENCRYPTED          ((NTSTATUS)0xC00004A6)
#define STATUS_RWRAW_ENCRYPTED_FILE_NOT_ENCRYPTED           ((NTSTATUS)0xC00004A7)
#define STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILEOFFSET ((NTSTATUS)0xC00004A8)
#define STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_FILERANGE  ((NTSTATUS)0xC00004A9)
#define STATUS_RWRAW_ENCRYPTED_INVALID_EDATAINFO_PARAMETER  ((NTSTATUS)0xC00004AA)
#define STATUS_FT_READ_FAILURE                  ((NTSTATUS)0xC00004AB)
#define STATUS_PATCH_CONFLICT                   ((NTSTATUS)0xC00004AC)
#define STATUS_STORAGE_RESERVE_ID_INVALID       ((NTSTATUS)0xC00004AD)
#define STATUS_STORAGE_RESERVE_DOES_NOT_EXIST   ((NTSTATUS)0xC00004AE)
#define STATUS_STORAGE_RESERVE_ALREADY_EXISTS   ((NTSTATUS)0xC00004AF)
#define STATUS_STORAGE_RESERVE_NOT_EMPTY        ((NTSTATUS)0xC00004B0)
#define STATUS_NOT_A_DAX_VOLUME                 ((NTSTATUS)0xC00004B1)
#define STATUS_NOT_DAX_MAPPABLE                 ((NTSTATUS)0xC00004B2)
#define STATUS_CASE_DIFFERING_NAMES_IN_DIR      ((NTSTATUS)0xC00004B3)
#define STATUS_FILE_NOT_SUPPORTED               ((NTSTATUS)0xC00004B4)
#define STATUS_NOT_SUPPORTED_WITH_BTT           ((NTSTATUS)0xC00004B5)
#define STATUS_ENCRYPTION_DISABLED              ((NTSTATUS)0xC00004B6)
#define STATUS_ENCRYPTING_METADATA_DISALLOWED   ((NTSTATUS)0xC00004B7)
#define STATUS_CANT_CLEAR_ENCRYPTION_FLAG       ((NTSTATUS)0xC00004B8)
#define STATUS_UNSATISFIED_DEPENDENCIES         ((NTSTATUS)0xC00004B9)
#define STATUS_CASE_SENSITIVE_PATH              ((NTSTATUS)0xC00004BA)
#define STATUS_INVALID_TASK_NAME                ((NTSTATUS)0xC0000500)
#define STATUS_INVALID_TASK_INDEX               ((NTSTATUS)0xC0000501)
#define STATUS_THREAD_ALREADY_IN_TASK           ((NTSTATUS)0xC0000502)
#define STATUS_CALLBACK_BYPASS                  ((NTSTATUS)0xC0000503)
#define STATUS_UNDEFINED_SCOPE                  ((NTSTATUS)0xC0000504)
#define STATUS_INVALID_CAP                      ((NTSTATUS)0xC0000505)
#define STATUS_NOT_GUI_PROCESS                  ((NTSTATUS)0xC0000506)
#define STATUS_DEVICE_HUNG                      ((NTSTATUS)0xC0000507)
#define STATUS_CONTAINER_ASSIGNED               ((NTSTATUS)0xC0000508)
#define STATUS_JOB_NO_CONTAINER                 ((NTSTATUS)0xC0000509)
#define STATUS_DEVICE_UNRESPONSIVE              ((NTSTATUS)0xC000050A)
#define STATUS_REPARSE_POINT_ENCOUNTERED        ((NTSTATUS)0xC000050B)
#define STATUS_ATTRIBUTE_NOT_PRESENT            ((NTSTATUS)0xC000050C)
#define STATUS_NOT_A_TIERED_VOLUME              ((NTSTATUS)0xC000050D)
#define STATUS_ALREADY_HAS_STREAM_ID            ((NTSTATUS)0xC000050E)
#define STATUS_JOB_NOT_EMPTY                    ((NTSTATUS)0xC000050F)
#define STATUS_ALREADY_INITIALIZED              ((NTSTATUS)0xC0000510)
#define STATUS_ENCLAVE_NOT_TERMINATED           ((NTSTATUS)0xC0000511)
#define STATUS_ENCLAVE_IS_TERMINATING           ((NTSTATUS)0xC0000512)
#define STATUS_SMB1_NOT_AVAILABLE               ((NTSTATUS)0xC0000513)
#define STATUS_SMR_GARBAGE_COLLECTION_REQUIRED  ((NTSTATUS)0xC0000514)
#define STATUS_INTERRUPTED                      ((NTSTATUS)0xC0000515)
#define STATUS_THREAD_NOT_RUNNING               ((NTSTATUS)0xC0000516)
#define STATUS_FAIL_FAST_EXCEPTION              ((NTSTATUS)0xC0000602)
#define STATUS_IMAGE_CERT_REVOKED               ((NTSTATUS)0xC0000603)
#define STATUS_DYNAMIC_CODE_BLOCKED             ((NTSTATUS)0xC0000604)
#define STATUS_IMAGE_CERT_EXPIRED               ((NTSTATUS)0xC0000605)
#define STATUS_STRICT_CFG_VIOLATION             ((NTSTATUS)0xC0000606)
#define STATUS_SET_CONTEXT_DENIED               ((NTSTATUS)0xC000060A)
#define STATUS_CROSS_PARTITION_VIOLATION        ((NTSTATUS)0xC000060B)
#define STATUS_PORT_CLOSED                      ((NTSTATUS)0xC0000700)
#define STATUS_MESSAGE_LOST                     ((NTSTATUS)0xC0000701)
#define STATUS_INVALID_MESSAGE                  ((NTSTATUS)0xC0000702)
#define STATUS_REQUEST_CANCELED                 ((NTSTATUS)0xC0000703)
#define STATUS_RECURSIVE_DISPATCH               ((NTSTATUS)0xC0000704)
#define STATUS_LPC_RECEIVE_BUFFER_EXPECTED      ((NTSTATUS)0xC0000705)
#define STATUS_LPC_INVALID_CONNECTION_USAGE     ((NTSTATUS)0xC0000706)
#define STATUS_LPC_REQUESTS_NOT_ALLOWED         ((NTSTATUS)0xC0000707)
#define STATUS_RESOURCE_IN_USE                  ((NTSTATUS)0xC0000708)
#define STATUS_HARDWARE_MEMORY_ERROR            ((NTSTATUS)0xC0000709)
#define STATUS_THREADPOOL_HANDLE_EXCEPTION      ((NTSTATUS)0xC000070A)
#define STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED         ((NTSTATUS)0xC000070B)
#define STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED ((NTSTATUS)0xC000070C)
#define STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED     ((NTSTATUS)0xC000070D)
#define STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED      ((NTSTATUS)0xC000070E)
#define STATUS_THREADPOOL_RELEASED_DURING_OPERATION              ((NTSTATUS)0xC000070F)
#define STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING ((NTSTATUS)0xC0000710)
#define STATUS_APC_RETURNED_WHILE_IMPERSONATING ((NTSTATUS)0xC0000711)
#define STATUS_PROCESS_IS_PROTECTED             ((NTSTATUS)0xC0000712)
#define STATUS_MCA_EXCEPTION                    ((NTSTATUS)0xC0000713)
#define STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE   ((NTSTATUS)0xC0000714)
#define STATUS_SYMLINK_CLASS_DISABLED           ((NTSTATUS)0xC0000715)
#define STATUS_INVALID_IDN_NORMALIZATION        ((NTSTATUS)0xC0000716)
#define STATUS_NO_UNICODE_TRANSLATION           ((NTSTATUS)0xC0000717)
#define STATUS_ALREADY_REGISTERED               ((NTSTATUS)0xC0000718)
#define STATUS_CONTEXT_MISMATCH                 ((NTSTATUS)0xC0000719)
#define STATUS_PORT_ALREADY_HAS_COMPLETION_LIST ((NTSTATUS)0xC000071A)
#define STATUS_CALLBACK_RETURNED_THREAD_PRIORITY ((NTSTATUS)0xC000071B)
#define STATUS_INVALID_THREAD                   ((NTSTATUS)0xC000071C)
#define STATUS_CALLBACK_RETURNED_TRANSACTION    ((NTSTATUS)0xC000071D)
#define STATUS_CALLBACK_RETURNED_LDR_LOCK       ((NTSTATUS)0xC000071E)
#define STATUS_CALLBACK_RETURNED_LANG           ((NTSTATUS)0xC000071F)
#define STATUS_CALLBACK_RETURNED_PRI_BACK       ((NTSTATUS)0xC0000720)
#define STATUS_CALLBACK_RETURNED_THREAD_AFFINITY ((NTSTATUS)0xC0000721)
#define STATUS_LPC_HANDLE_COUNT_EXCEEDED        ((NTSTATUS)0xC0000722)
#define STATUS_EXECUTABLE_MEMORY_WRITE          ((NTSTATUS)0xC0000723)
#define STATUS_KERNEL_EXECUTABLE_MEMORY_WRITE   ((NTSTATUS)0xC0000724)
#define STATUS_ATTACHED_EXECUTABLE_MEMORY_WRITE ((NTSTATUS)0xC0000725)
#define STATUS_TRIGGERED_EXECUTABLE_MEMORY_WRITE ((NTSTATUS)0xC0000726)
#define STATUS_DISK_REPAIR_DISABLED             ((NTSTATUS)0xC0000800)
#define STATUS_DS_DOMAIN_RENAME_IN_PROGRESS     ((NTSTATUS)0xC0000801)
#define STATUS_DISK_QUOTA_EXCEEDED              ((NTSTATUS)0xC0000802)
#define STATUS_CONTENT_BLOCKED                  ((NTSTATUS)0xC0000804)
#define STATUS_BAD_CLUSTERS                     ((NTSTATUS)0xC0000805)
#define STATUS_VOLUME_DIRTY                     ((NTSTATUS)0xC0000806)

#define STATUS_DISK_REPAIR_UNSUCCESSFUL         ((NTSTATUS)0xC0000808)
#define STATUS_CORRUPT_LOG_OVERFULL             ((NTSTATUS)0xC0000809)
#define STATUS_CORRUPT_LOG_CORRUPTED            ((NTSTATUS)0xC000080A)
#define STATUS_CORRUPT_LOG_UNAVAILABLE          ((NTSTATUS)0xC000080B)
#define STATUS_CORRUPT_LOG_DELETED_FULL         ((NTSTATUS)0xC000080C)
#define STATUS_CORRUPT_LOG_CLEARED              ((NTSTATUS)0xC000080D)
#define STATUS_ORPHAN_NAME_EXHAUSTED            ((NTSTATUS)0xC000080E)
#define STATUS_PROACTIVE_SCAN_IN_PROGRESS       ((NTSTATUS)0xC000080F)
#define STATUS_ENCRYPTED_IO_NOT_POSSIBLE        ((NTSTATUS)0xC0000810)
#define STATUS_CORRUPT_LOG_UPLEVEL_RECORDS      ((NTSTATUS)0xC0000811)
#define STATUS_FILE_CHECKED_OUT                 ((NTSTATUS)0xC0000901)
#define STATUS_CHECKOUT_REQUIRED                ((NTSTATUS)0xC0000902)
#define STATUS_BAD_FILE_TYPE                    ((NTSTATUS)0xC0000903)
#define STATUS_FILE_TOO_LARGE                   ((NTSTATUS)0xC0000904)
#define STATUS_FORMS_AUTH_REQUIRED              ((NTSTATUS)0xC0000905)
#define STATUS_VIRUS_INFECTED                   ((NTSTATUS)0xC0000906)
#define STATUS_VIRUS_DELETED                    ((NTSTATUS)0xC0000907)
#define STATUS_BAD_MCFG_TABLE                   ((NTSTATUS)0xC0000908)
#define STATUS_CANNOT_BREAK_OPLOCK              ((NTSTATUS)0xC0000909)
#define STATUS_BAD_KEY                          ((NTSTATUS)0xC000090A)
#define STATUS_BAD_DATA                         ((NTSTATUS)0xC000090B)
#define STATUS_NO_KEY                           ((NTSTATUS)0xC000090C)
#define STATUS_FILE_HANDLE_REVOKED              ((NTSTATUS)0xC0000910)
#define STATUS_WOW_ASSERTION                    ((NTSTATUS)0xC0009898)
#define STATUS_INVALID_SIGNATURE                ((NTSTATUS)0xC000A000)
#define STATUS_HMAC_NOT_SUPPORTED               ((NTSTATUS)0xC000A001)
#define STATUS_IPSEC_QUEUE_OVERFLOW             ((NTSTATUS)0xC000A010)
#define STATUS_ND_QUEUE_OVERFLOW                ((NTSTATUS)0xC000A011)
#define STATUS_HOPLIMIT_EXCEEDED                ((NTSTATUS)0xC000A012)
#define STATUS_PROTOCOL_NOT_SUPPORTED           ((NTSTATUS)0xC000A013)

#define RPC_NT_INVALID_STRING_BINDING    ((NTSTATUS)0xC0020001)
#define RPC_NT_WRONG_KIND_OF_BINDING     ((NTSTATUS)0xC0020002)
#define RPC_NT_INVALID_BINDING           ((NTSTATUS)0xC0020003)
#define RPC_NT_PROTSEQ_NOT_SUPPORTED     ((NTSTATUS)0xC0020004)
#define RPC_NT_INVALID_RPC_PROTSEQ       ((NTSTATUS)0xC0020005)
#define RPC_NT_INVALID_STRING_UUID       ((NTSTATUS)0xC0020006)
#define RPC_NT_INVALID_ENDPOINT_FORMAT   ((NTSTATUS)0xC0020007)
#define RPC_NT_INVALID_NET_ADDR          ((NTSTATUS)0xC0020008)
#define RPC_NT_NO_ENDPOINT_FOUND         ((NTSTATUS)0xC0020009)
#define RPC_NT_INVALID_TIMEOUT           ((NTSTATUS)0xC002000A)
#define RPC_NT_OBJECT_NOT_FOUND          ((NTSTATUS)0xC002000B)
#define RPC_NT_ALREADY_REGISTERED        ((NTSTATUS)0xC002000C)
#define RPC_NT_TYPE_ALREADY_REGISTERED   ((NTSTATUS)0xC002000D)
#define RPC_NT_ALREADY_LISTENING         ((NTSTATUS)0xC002000E)
#define RPC_NT_NO_PROTSEQS_REGISTERED    ((NTSTATUS)0xC002000F)
#define RPC_NT_NOT_LISTENING             ((NTSTATUS)0xC0020010)
#define RPC_NT_UNKNOWN_MGR_TYPE          ((NTSTATUS)0xC0020011)
#define RPC_NT_UNKNOWN_IF                ((NTSTATUS)0xC0020012)
#define RPC_NT_NO_BINDINGS               ((NTSTATUS)0xC0020013)
#define RPC_NT_NO_PROTSEQS               ((NTSTATUS)0xC0020014)
#define RPC_NT_CANT_CREATE_ENDPOINT      ((NTSTATUS)0xC0020015)
#define RPC_NT_OUT_OF_RESOURCES          ((NTSTATUS)0xC0020016)
#define RPC_NT_SERVER_UNAVAILABLE        ((NTSTATUS)0xC0020017)
#define RPC_NT_SERVER_TOO_BUSY           ((NTSTATUS)0xC0020018)
#define RPC_NT_INVALID_NETWORK_OPTIONS   ((NTSTATUS)0xC0020019)
#define RPC_NT_NO_CALL_ACTIVE            ((NTSTATUS)0xC002001A)
#define RPC_NT_CALL_FAILED               ((NTSTATUS)0xC002001B)
#define RPC_NT_CALL_FAILED_DNE           ((NTSTATUS)0xC002001C)
#define RPC_NT_PROTOCOL_ERROR            ((NTSTATUS)0xC002001D)
#define RPC_NT_UNSUPPORTED_TRANS_SYN     ((NTSTATUS)0xC002001F)
#define RPC_NT_UNSUPPORTED_TYPE          ((NTSTATUS)0xC0020021)
#define RPC_NT_INVALID_TAG               ((NTSTATUS)0xC0020022)
#define RPC_NT_INVALID_BOUND             ((NTSTATUS)0xC0020023)
#define RPC_NT_NO_ENTRY_NAME             ((NTSTATUS)0xC0020024)
#define RPC_NT_INVALID_NAME_SYNTAX       ((NTSTATUS)0xC0020025)
#define RPC_NT_UNSUPPORTED_NAME_SYNTAX   ((NTSTATUS)0xC0020026)
#define RPC_NT_UUID_NO_ADDRESS           ((NTSTATUS)0xC0020028)
#define RPC_NT_DUPLICATE_ENDPOINT        ((NTSTATUS)0xC0020029)
#define RPC_NT_UNKNOWN_AUTHN_TYPE        ((NTSTATUS)0xC002002A)
#define RPC_NT_MAX_CALLS_TOO_SMALL       ((NTSTATUS)0xC002002B)
#define RPC_NT_STRING_TOO_LONG           ((NTSTATUS)0xC002002C)
#define RPC_NT_PROTSEQ_NOT_FOUND         ((NTSTATUS)0xC002002D)
#define RPC_NT_PROCNUM_OUT_OF_RANGE      ((NTSTATUS)0xC002002E)
#define RPC_NT_BINDING_HAS_NO_AUTH       ((NTSTATUS)0xC002002F)
#define RPC_NT_UNKNOWN_AUTHN_SERVICE     ((NTSTATUS)0xC0020030)
#define RPC_NT_UNKNOWN_AUTHN_LEVEL       ((NTSTATUS)0xC0020031)
#define RPC_NT_INVALID_AUTH_IDENTITY     ((NTSTATUS)0xC0020032)
#define RPC_NT_UNKNOWN_AUTHZ_SERVICE     ((NTSTATUS)0xC0020033)
#define EPT_NT_INVALID_ENTRY             ((NTSTATUS)0xC0020034)
#define EPT_NT_CANT_PERFORM_OP           ((NTSTATUS)0xC0020035)
#define EPT_NT_NOT_REGISTERED            ((NTSTATUS)0xC0020036)
#define RPC_NT_NOTHING_TO_EXPORT         ((NTSTATUS)0xC0020037)
#define RPC_NT_INCOMPLETE_NAME           ((NTSTATUS)0xC0020038)
#define RPC_NT_INVALID_VERS_OPTION       ((NTSTATUS)0xC0020039)
#define RPC_NT_NO_MORE_MEMBERS           ((NTSTATUS)0xC002003A)
#define RPC_NT_NOT_ALL_OBJS_UNEXPORTED   ((NTSTATUS)0xC002003B)
#define RPC_NT_INTERFACE_NOT_FOUND       ((NTSTATUS)0xC002003C)
#define RPC_NT_ENTRY_ALREADY_EXISTS      ((NTSTATUS)0xC002003D)
#define RPC_NT_ENTRY_NOT_FOUND           ((NTSTATUS)0xC002003E)
#define RPC_NT_NAME_SERVICE_UNAVAILABLE  ((NTSTATUS)0xC002003F)
#define RPC_NT_INVALID_NAF_ID            ((NTSTATUS)0xC0020040)
#define RPC_NT_CANNOT_SUPPORT            ((NTSTATUS)0xC0020041)
#define RPC_NT_NO_CONTEXT_AVAILABLE      ((NTSTATUS)0xC0020042)
#define RPC_NT_INTERNAL_ERROR            ((NTSTATUS)0xC0020043)
#define RPC_NT_ZERO_DIVIDE               ((NTSTATUS)0xC0020044)
#define RPC_NT_ADDRESS_ERROR             ((NTSTATUS)0xC0020045)
#define RPC_NT_FP_DIV_ZERO               ((NTSTATUS)0xC0020046)
#define RPC_NT_FP_UNDERFLOW              ((NTSTATUS)0xC0020047)
#define RPC_NT_FP_OVERFLOW               ((NTSTATUS)0xC0020048)
#define RPC_NT_CALL_IN_PROGRESS          ((NTSTATUS)0xC0020049)
#define RPC_NT_NO_MORE_BINDINGS          ((NTSTATUS)0xC002004A)
#define RPC_NT_GROUP_MEMBER_NOT_FOUND    ((NTSTATUS)0xC002004B)
#define EPT_NT_CANT_CREATE               ((NTSTATUS)0xC002004C)
#define RPC_NT_INVALID_OBJECT            ((NTSTATUS)0xC002004D)
#define RPC_NT_NO_INTERFACES             ((NTSTATUS)0xC002004F)
#define RPC_NT_CALL_CANCELLED            ((NTSTATUS)0xC0020050)
#define RPC_NT_BINDING_INCOMPLETE        ((NTSTATUS)0xC0020051)
#define RPC_NT_COMM_FAILURE              ((NTSTATUS)0xC0020052)
#define RPC_NT_UNSUPPORTED_AUTHN_LEVEL   ((NTSTATUS)0xC0020053)
#define RPC_NT_NO_PRINC_NAME             ((NTSTATUS)0xC0020054)
#define RPC_NT_NOT_RPC_ERROR             ((NTSTATUS)0xC0020055)
#define RPC_NT_SEC_PKG_ERROR             ((NTSTATUS)0xC0020057)
#define RPC_NT_NOT_CANCELLED             ((NTSTATUS)0xC0020058)
#define RPC_NT_INVALID_ASYNC_HANDLE      ((NTSTATUS)0xC0020062)
#define RPC_NT_INVALID_ASYNC_CALL        ((NTSTATUS)0xC0020063)

#define RPC_NT_NO_MORE_ENTRIES           ((NTSTATUS)0xC0030001)
#define RPC_NT_SS_CHAR_TRANS_OPEN_FAIL   ((NTSTATUS)0xC0030002)
#define RPC_NT_SS_CHAR_TRANS_SHORT_FILE  ((NTSTATUS)0xC0030003)
#define RPC_NT_SS_IN_NULL_CONTEXT        ((NTSTATUS)0xC0030004)
#define RPC_NT_SS_CONTEXT_MISMATCH       ((NTSTATUS)0xC0030005)
#define RPC_NT_SS_CONTEXT_DAMAGED        ((NTSTATUS)0xC0030006)
#define RPC_NT_SS_HANDLES_MISMATCH       ((NTSTATUS)0xC0030007)
#define RPC_NT_SS_CANNOT_GET_CALL_HANDLE ((NTSTATUS)0xC0030008)
#define RPC_NT_NULL_REF_POINTER          ((NTSTATUS)0xC0030009)
#define RPC_NT_ENUM_VALUE_OUT_OF_RANGE   ((NTSTATUS)0xC003000A)
#define RPC_NT_BYTE_COUNT_TOO_SMALL      ((NTSTATUS)0xC003000B)
#define RPC_NT_BAD_STUB_DATA             ((NTSTATUS)0xC003000C)
#define RPC_NT_INVALID_ES_ACTION         ((NTSTATUS)0xC0030059)
#define RPC_NT_WRONG_ES_VERSION          ((NTSTATUS)0xC003005A)
#define RPC_NT_WRONG_STUB_VERSION        ((NTSTATUS)0xC003005B)
#define RPC_NT_INVALID_PIPE_OBJECT       ((NTSTATUS)0xC003005C)
#define RPC_NT_INVALID_PIPE_OPERATION    ((NTSTATUS)0xC003005D)
#define RPC_NT_WRONG_PIPE_VERSION        ((NTSTATUS)0xC003005E)
#define RPC_NT_PIPE_CLOSED               ((NTSTATUS)0xC003005F)
#define RPC_NT_PIPE_DISCIPLINE_ERROR     ((NTSTATUS)0xC0030060)
#define RPC_NT_PIPE_EMPTY                ((NTSTATUS)0xC0030061)

#define STATUS_PNP_BAD_MPS_TABLE          ((NTSTATUS)0xC0040035)
#define STATUS_PNP_TRANSLATION_FAILED     ((NTSTATUS)0xC0040036)
#define STATUS_PNP_IRQ_TRANSLATION_FAILED ((NTSTATUS)0xC0040037)
#define STATUS_PNP_INVALID_ID             ((NTSTATUS)0xC0040038)

#define STATUS_ACPI_INVALID_OPCODE              ((NTSTATUS)0xC0140001L)
#define STATUS_ACPI_STACK_OVERFLOW              ((NTSTATUS)0xC0140002L)
#define STATUS_ACPI_ASSERT_FAILED               ((NTSTATUS)0xC0140003L)
#define STATUS_ACPI_INVALID_INDEX               ((NTSTATUS)0xC0140004L)
#define STATUS_ACPI_INVALID_ARGUMENT            ((NTSTATUS)0xC0140005L)
#define STATUS_ACPI_FATAL                       ((NTSTATUS)0xC0140006L)
#define STATUS_ACPI_INVALID_SUPERNAME           ((NTSTATUS)0xC0140007L)
#define STATUS_ACPI_INVALID_ARGTYPE             ((NTSTATUS)0xC0140008L)
#define STATUS_ACPI_INVALID_OBJTYPE             ((NTSTATUS)0xC0140009L)
#define STATUS_ACPI_INVALID_TARGETTYPE          ((NTSTATUS)0xC014000AL)
#define STATUS_ACPI_INCORRECT_ARGUMENT_COUNT    ((NTSTATUS)0xC014000BL)
#define STATUS_ACPI_ADDRESS_NOT_MAPPED          ((NTSTATUS)0xC014000CL)
#define STATUS_ACPI_INVALID_EVENTTYPE           ((NTSTATUS)0xC014000DL)
#define STATUS_ACPI_HANDLER_COLLISION           ((NTSTATUS)0xC014000EL)
#define STATUS_ACPI_INVALID_DATA                ((NTSTATUS)0xC014000FL)
#define STATUS_ACPI_INVALID_REGION              ((NTSTATUS)0xC0140010L)
#define STATUS_ACPI_INVALID_ACCESS_SIZE         ((NTSTATUS)0xC0140011L)
#define STATUS_ACPI_ACQUIRE_GLOBAL_LOCK         ((NTSTATUS)0xC0140012L)
#define STATUS_ACPI_ALREADY_INITIALIZED         ((NTSTATUS)0xC0140013L)
#define STATUS_ACPI_NOT_INITIALIZED             ((NTSTATUS)0xC0140014L)
#define STATUS_ACPI_INVALID_MUTEX_LEVEL         ((NTSTATUS)0xC0140015L)
#define STATUS_ACPI_MUTEX_NOT_OWNED             ((NTSTATUS)0xC0140016L)
#define STATUS_ACPI_MUTEX_NOT_OWNER             ((NTSTATUS)0xC0140017L)
#define STATUS_ACPI_RS_ACCESS                   ((NTSTATUS)0xC0140018L)
#define STATUS_ACPI_INVALID_TABLE               ((NTSTATUS)0xC0140019L)
#define STATUS_ACPI_REG_HANDLER_FAILED          ((NTSTATUS)0xC0140020L)
#define STATUS_ACPI_POWER_REQUEST_FAILED        ((NTSTATUS)0xC0140021L)

#define STATUS_CTX_WINSTATION_NAME_INVALID      ((NTSTATUS)0xC00A0001)
#define STATUS_CTX_INVALID_PD                   ((NTSTATUS)0xC00A0002)
#define STATUS_CTX_PD_NOT_FOUND                 ((NTSTATUS)0xC00A0003)
#define STATUS_CTX_CLOSE_PENDING                ((NTSTATUS)0xC00A0006)
#define STATUS_CTX_NO_OUTBUF                    ((NTSTATUS)0xC00A0007)
#define STATUS_CTX_MODEM_INF_NOT_FOUND          ((NTSTATUS)0xC00A0008)
#define STATUS_CTX_INVALID_MODEMNAME            ((NTSTATUS)0xC00A0009)
#define STATUS_CTX_RESPONSE_ERROR               ((NTSTATUS)0xC00A000A)
#define STATUS_CTX_MODEM_RESPONSE_TIMEOUT       ((NTSTATUS)0xC00A000B)
#define STATUS_CTX_MODEM_RESPONSE_NO_CARRIER    ((NTSTATUS)0xC00A000C)
#define STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE   ((NTSTATUS)0xC00A000D)
#define STATUS_CTX_MODEM_RESPONSE_BUSY          ((NTSTATUS)0xC00A000E)
#define STATUS_CTX_MODEM_RESPONSE_VOICE         ((NTSTATUS)0xC00A000F)
#define STATUS_CTX_TD_ERROR                     ((NTSTATUS)0xC00A0010)
#define STATUS_CTX_LICENSE_CLIENT_INVALID       ((NTSTATUS)0xC00A0012)
#define STATUS_CTX_LICENSE_NOT_AVAILABLE        ((NTSTATUS)0xC00A0013)
#define STATUS_CTX_LICENSE_EXPIRED              ((NTSTATUS)0xC00A0014)
#define STATUS_CTX_WINSTATION_NOT_FOUND         ((NTSTATUS)0xC00A0015)
#define STATUS_CTX_WINSTATION_NAME_COLLISION    ((NTSTATUS)0xC00A0016)
#define STATUS_CTX_WINSTATION_BUSY              ((NTSTATUS)0xC00A0017)
#define STATUS_CTX_BAD_VIDEO_MODE               ((NTSTATUS)0xC00A0018)
#define STATUS_CTX_GRAPHICS_INVALID             ((NTSTATUS)0xC00A0022)
#define STATUS_CTX_NOT_CONSOLE                  ((NTSTATUS)0xC00A0024)
#define STATUS_CTX_CLIENT_QUERY_TIMEOUT         ((NTSTATUS)0xC00A0026)
#define STATUS_CTX_CONSOLE_DISCONNECT           ((NTSTATUS)0xC00A0027)
#define STATUS_CTX_CONSOLE_CONNECT              ((NTSTATUS)0xC00A0028)
#define STATUS_CTX_SHADOW_DENIED                ((NTSTATUS)0xC00A002A)
#define STATUS_CTX_WINSTATION_ACCESS_DENIED     ((NTSTATUS)0xC00A002B)
#define STATUS_CTX_INVALID_WD                   ((NTSTATUS)0xC00A002E)
#define STATUS_CTX_WD_NOT_FOUND                 ((NTSTATUS)0xC00A002F)
#define STATUS_CTX_SHADOW_INVALID               ((NTSTATUS)0xC00A0030)
#define STATUS_CTX_SHADOW_DISABLED              ((NTSTATUS)0xC00A0031)
#define STATUS_RDP_PROTOCOL_ERROR               ((NTSTATUS)0xC00A0032)
#define STATUS_CTX_CLIENT_LICENSE_NOT_SET       ((NTSTATUS)0xC00A0033)
#define STATUS_CTX_CLIENT_LICENSE_IN_USE        ((NTSTATUS)0xC00A0034)
#define STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE  ((NTSTATUS)0xC00A0035)
#define STATUS_CTX_SHADOW_NOT_RUNNING           ((NTSTATUS)0xC00A0036)

#define STATUS_CLUSTER_INVALID_NODE             ((NTSTATUS)0xC0130001)
#define STATUS_CLUSTER_NODE_EXISTS              ((NTSTATUS)0xC0130002)
#define STATUS_CLUSTER_JOIN_IN_PROGRESS         ((NTSTATUS)0xC0130003)
#define STATUS_CLUSTER_NODE_NOT_FOUND           ((NTSTATUS)0xC0130004)
#define STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND     ((NTSTATUS)0xC0130005)
#define STATUS_CLUSTER_NETWORK_EXISTS           ((NTSTATUS)0xC0130006)
#define STATUS_CLUSTER_NETWORK_NOT_FOUND        ((NTSTATUS)0xC0130007)
#define STATUS_CLUSTER_NETINTERFACE_EXISTS      ((NTSTATUS)0xC0130008)
#define STATUS_CLUSTER_NETINTERFACE_NOT_FOUND   ((NTSTATUS)0xC0130009)
#define STATUS_CLUSTER_INVALID_REQUEST          ((NTSTATUS)0xC013000A)
#define STATUS_CLUSTER_INVALID_NETWORK_PROVIDER ((NTSTATUS)0xC013000B)
#define STATUS_CLUSTER_NODE_DOWN                ((NTSTATUS)0xC013000C)
#define STATUS_CLUSTER_NODE_UNREACHABLE         ((NTSTATUS)0xC013000D)
#define STATUS_CLUSTER_NODE_NOT_MEMBER          ((NTSTATUS)0xC013000E)
#define STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS     ((NTSTATUS)0xC013000F)
#define STATUS_CLUSTER_INVALID_NETWORK          ((NTSTATUS)0xC0130010)
#define STATUS_CLUSTER_NO_NET_ADAPTERS          ((NTSTATUS)0xC0130011)
#define STATUS_CLUSTER_NODE_UP                  ((NTSTATUS)0xC0130012)
#define STATUS_CLUSTER_NODE_PAUSED              ((NTSTATUS)0xC0130013)
#define STATUS_CLUSTER_NODE_NOT_PAUSED          ((NTSTATUS)0xC0130014)
#define STATUS_CLUSTER_NO_SECURITY_CONTEXT      ((NTSTATUS)0xC0130015)
#define STATUS_CLUSTER_NETWORK_NOT_INTERNAL     ((NTSTATUS)0xC0130016)
#define STATUS_CLUSTER_POISONED                 ((NTSTATUS)0xC0130017)

#define STATUS_SXS_SECTION_NOT_FOUND            ((NTSTATUS)0xC0150001)
#define STATUS_SXS_CANT_GEN_ACTCTX              ((NTSTATUS)0xC0150002)
#define STATUS_SXS_INVALID_ACTCTXDATA_FORMAT    ((NTSTATUS)0xC0150003)
#define STATUS_SXS_ASSEMBLY_NOT_FOUND           ((NTSTATUS)0xC0150004)
#define STATUS_SXS_MANIFEST_FORMAT_ERROR        ((NTSTATUS)0xC0150005)
#define STATUS_SXS_MANIFEST_PARSE_ERROR         ((NTSTATUS)0xC0150006)
#define STATUS_SXS_ACTIVATION_CONTEXT_DISABLED  ((NTSTATUS)0xC0150007)
#define STATUS_SXS_KEY_NOT_FOUND                ((NTSTATUS)0xC0150008)
#define STATUS_SXS_VERSION_CONFLICT             ((NTSTATUS)0xC0150009)
#define STATUS_SXS_WRONG_SECTION_TYPE           ((NTSTATUS)0xC015000A)
#define STATUS_SXS_THREAD_QUERIES_DISABLED      ((NTSTATUS)0xC015000B)
#define STATUS_SXS_ASSEMBLY_MISSING             ((NTSTATUS)0xC015000C)
#define STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET  ((NTSTATUS)0xC015000E)
#define STATUS_SXS_EARLY_DEACTIVATION           ((NTSTATUS)0xC015000F)
#define STATUS_SXS_INVALID_DEACTIVATION         ((NTSTATUS)0xC0150010)
#define STATUS_SXS_MULTIPLE_DEACTIVATION        ((NTSTATUS)0xC0150011)
#define STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY ((NTSTATUS)0xC0150012)
#define STATUS_SXS_PROCESS_TERMINATION_REQUESTED ((NTSTATUS)0xC0150013)
#define STATUS_SXS_CORRUPT_ACTIVATION_STACK ((NTSTATUS)0xC0150014)
#define STATUS_SXS_CORRUPTION                   ((NTSTATUS)0xC0150015)
#define STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE  ((NTSTATUS) 0xC0150016)
#define STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME   ((NTSTATUS) 0xC0150017)
#define STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE      ((NTSTATUS) 0xC0150018)
#define STATUS_SXS_IDENTITY_PARSE_ERROR              ((NTSTATUS) 0xC0150019)
#define STATUS_SXS_COMPONENT_STORE_CORRUPT           ((NTSTATUS) 0xC015001A)
#define STATUS_SXS_FILE_HASH_MISMATCH                ((NTSTATUS) 0xC015001B)
#define STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT    ((NTSTATUS) 0xC015001C)
#define STATUS_SXS_IDENTITIES_DIFFERENT              ((NTSTATUS) 0xC015001D)
#define STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT      ((NTSTATUS) 0xC015001E)
#define STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY         ((NTSTATUS) 0xC015001F)
#define STATUS_ADVANCED_INSTALLER_FAILED             ((NTSTATUS) 0xC0150020)
#define STATUS_XML_ENCODING_MISMATCH                 ((NTSTATUS) 0xC0150021)
#define STATUS_SXS_MANIFEST_TOO_BIG                  ((NTSTATUS) 0xC0150022)
#define STATUS_SXS_SETTING_NOT_REGISTERED            ((NTSTATUS) 0xC0150023)
#define STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE    ((NTSTATUS) 0xC0150024)
#define STATUS_SMI_PRIMITIVE_INSTALLER_FAILED        ((NTSTATUS) 0xC0150025)
#define STATUS_GENERIC_COMMAND_FAILED                ((NTSTATUS) 0xC0150026)
#define STATUS_SXS_FILE_HASH_MISSING                 ((NTSTATUS) 0xC0150027)


#define STATUS_FLT_NO_HANDLER_DEFINED           ((NTSTATUS)0xC01C0001L)
#define STATUS_FLT_CONTEXT_ALREADY_DEFINED      ((NTSTATUS)0xC01C0002L)
#define STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST ((NTSTATUS)0xC01C0003L)
#define STATUS_FLT_DISALLOW_FAST_IO             ((NTSTATUS)0xC01C0004L)
#define STATUS_FLT_INVALID_NAME_REQUEST         ((NTSTATUS)0xC01C0005L)
#define STATUS_FLT_NOT_SAFE_TO_POST_OPERATION   ((NTSTATUS)0xC01C0006L)
#define STATUS_FLT_NOT_INITIALIZED              ((NTSTATUS)0xC01C0007L)
#define STATUS_FLT_FILTER_NOT_READY             ((NTSTATUS)0xC01C0008L)
#define STATUS_FLT_POST_OPERATION_CLEANUP       ((NTSTATUS)0xC01C0009L)
#define STATUS_FLT_INTERNAL_ERROR               ((NTSTATUS)0xC01C000AL)
#define STATUS_FLT_DELETING_OBJECT              ((NTSTATUS)0xC01C000BL)
#define STATUS_FLT_MUST_BE_NONPAGED_POOL        ((NTSTATUS)0xC01C000CL)
#define STATUS_FLT_DUPLICATE_ENTRY              ((NTSTATUS)0xC01C000DL)
#define STATUS_FLT_CBDQ_DISABLED                ((NTSTATUS)0xC01C000EL)
#define STATUS_FLT_DO_NOT_ATTACH                ((NTSTATUS)0xC01C000FL)
#define STATUS_FLT_DO_NOT_DETACH                ((NTSTATUS)0xC01C0010L)
#define STATUS_FLT_INSTANCE_ALTITUDE_COLLISION  ((NTSTATUS)0xC01C0011L)
#define STATUS_FLT_INSTANCE_NAME_COLLISION      ((NTSTATUS)0xC01C0012L)
#define STATUS_FLT_FILTER_NOT_FOUND             ((NTSTATUS)0xC01C0013L)
#define STATUS_FLT_VOLUME_NOT_FOUND             ((NTSTATUS)0xC01C0014L)
#define STATUS_FLT_INSTANCE_NOT_FOUND           ((NTSTATUS)0xC01C0015L)
#define STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND ((NTSTATUS)0xC01C0016L)
#define STATUS_FLT_INVALID_CONTEXT_REGISTRATION ((NTSTATUS)0xC01C0017L)
#define STATUS_FLT_NAME_CACHE_MISS              ((NTSTATUS)0xC01C0018L)
#define STATUS_FLT_NO_DEVICE_OBJECT             ((NTSTATUS)0xC01C0019L)
#define STATUS_FLT_VOLUME_ALREADY_MOUNTED       ((NTSTATUS)0xC01C001AL)
#define STATUS_FLT_ALREADY_ENLISTED             ((NTSTATUS)0xC01C001BL)
#define STATUS_FLT_CONTEXT_ALREADY_LINKED       ((NTSTATUS)0xC01C001CL)
#define STATUS_FLT_NO_WAITER_FOR_REPLY          ((NTSTATUS)0xC01C0020L)
#define STATUS_FLT_REGISTRATION_BUSY            ((NTSTATUS)0xC01C0023L)


#define STATUS_FVE_LOCKED_VOLUME                        ((NTSTATUS)0xC0210000)
#define STATUS_FVE_NOT_ENCRYPTED                        ((NTSTATUS)0xC0210001)
#define STATUS_FVE_BAD_INFORMATION                      ((NTSTATUS)0xC0210002)
#define STATUS_FVE_TOO_SMALL                            ((NTSTATUS)0xC0210003)
#define STATUS_FVE_FAILED_WRONG_FS                      ((NTSTATUS)0xC0210004)
#define STATUS_FVE_FAILED_BAD_FS                        ((NTSTATUS)0xC0210005)
#define STATUS_FVE_FS_NOT_EXTENDED                      ((NTSTATUS)0xC0210006)
#define STATUS_FVE_FS_MOUNTED                           ((NTSTATUS)0xC0210007)
#define STATUS_FVE_NO_LICENSE                           ((NTSTATUS)0xC0210008)
#define STATUS_FVE_ACTION_NOT_ALLOWED                   ((NTSTATUS)0xC0210009)
#define STATUS_FVE_BAD_DATA                             ((NTSTATUS)0xC021000A)
#define STATUS_FVE_VOLUME_NOT_BOUND                     ((NTSTATUS)0xC021000B)
#define STATUS_FVE_NOT_DATA_VOLUME                      ((NTSTATUS)0xC021000C)
#define STATUS_FVE_CONV_READ_ERROR                      ((NTSTATUS)0xC021000D)
#define STATUS_FVE_CONV_WRITE_ERROR                     ((NTSTATUS)0xC021000E)
#define STATUS_FVE_OVERLAPPED_UPDATE                    ((NTSTATUS)0xC021000F)
#define STATUS_FVE_FAILED_SECTOR_SIZE                   ((NTSTATUS)0xC0210010)
#define STATUS_FVE_FAILED_AUTHENTICATION                ((NTSTATUS)0xC0210011)
#define STATUS_FVE_NOT_OS_VOLUME                        ((NTSTATUS)0xC0210012)
#define STATUS_FVE_KEYFILE_NOT_FOUND                    ((NTSTATUS)0xC0210013)
#define STATUS_FVE_KEYFILE_INVALID                      ((NTSTATUS)0xC0210014)
#define STATUS_FVE_KEYFILE_NO_VMK                       ((NTSTATUS)0xC0210015)
#define STATUS_FVE_TPM_DISABLED                         ((NTSTATUS)0xC0210016)
#define STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO                ((NTSTATUS)0xC0210017)
#define STATUS_FVE_TPM_INVALID_PCR                      ((NTSTATUS)0xC0210018)
#define STATUS_FVE_TPM_NO_VMK                           ((NTSTATUS)0xC0210019)
#define STATUS_FVE_PIN_INVALID                          ((NTSTATUS)0xC021001A)
#define STATUS_FVE_AUTH_INVALID_APPLICATION             ((NTSTATUS)0xC021001B)
#define STATUS_FVE_AUTH_INVALID_CONFIG                  ((NTSTATUS)0xC021001C)
#define STATUS_FVE_DEBUGGER_ENABLED                     ((NTSTATUS)0xC021001D)
#define STATUS_FVE_DRY_RUN_FAILED                       ((NTSTATUS)0xC021001E)
#define STATUS_FVE_BAD_METADATA_POINTER                 ((NTSTATUS)0xC021001F)
#define STATUS_FVE_OLD_METADATA_COPY                    ((NTSTATUS)0xC0210020)
#define STATUS_FVE_REBOOT_REQUIRED                      ((NTSTATUS)0xC0210021)
#define STATUS_FVE_RAW_ACCESS                           ((NTSTATUS)0xC0210022)
#define STATUS_FVE_RAW_BLOCKED                          ((NTSTATUS)0xC0210023)
#define STATUS_FVE_NO_FEATURE_LICENSE                   ((NTSTATUS)0xC0210026)
#define STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED  ((NTSTATUS)0xC0210027)
#define STATUS_FVE_CONV_RECOVERY_FAILED                 ((NTSTATUS)0xC0210028)
#define STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG            ((NTSTATUS)0xC0210029)
#define STATUS_FVE_VOLUME_TOO_SMALL                     ((NTSTATUS)0xC0210030)

#define IMAGE_FILE_MACHINE_AMD64      0x8664
#define IMAGE_FILE_MACHINE_NATIVE IMAGE_FILE_MACHINE_AMD64



//
// Global Flags
//
#define FLG_STOP_ON_EXCEPTION                   0x00000001
#define FLG_SHOW_LDR_SNAPS                      0x00000002
#define FLG_DEBUG_INITIAL_COMMAND               0x00000004
#define FLG_STOP_ON_HUNG_GUI                    0x00000008
#define FLG_HEAP_ENABLE_TAIL_CHECK              0x00000010
#define FLG_HEAP_ENABLE_FREE_CHECK              0x00000020
#define FLG_HEAP_VALIDATE_PARAMETERS            0x00000040
#define FLG_HEAP_VALIDATE_ALL                   0x00000080
#define FLG_APPLICATION_VERIFIER                0x00000100
#define FLG_POOL_ENABLE_TAGGING                 0x00000400
#define FLG_HEAP_ENABLE_TAGGING                 0x00000800
#define FLG_USER_STACK_TRACE_DB                 0x00001000
#define FLG_KERNEL_STACK_TRACE_DB               0x00002000
#define FLG_MAINTAIN_OBJECT_TYPELIST            0x00004000
#define FLG_HEAP_ENABLE_TAG_BY_DLL              0x00008000
#define FLG_DISABLE_STACK_EXTENSION             0x00010000
#define FLG_ENABLE_CSRDEBUG                     0x00020000
#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD           0x00040000
#define FLG_DISABLE_PAGE_KERNEL_STACKS          0x00080000
#if (NTDDI_VERSION < NTDDI_WINXP)
#define FLG_HEAP_ENABLE_CALL_TRACING            0x00100000
#else
#define FLG_ENABLE_SYSTEM_CRIT_BREAKS           0x00100000
#endif
#define FLG_HEAP_DISABLE_COALESCING             0x00200000
#define FLG_ENABLE_CLOSE_EXCEPTIONS             0x00400000
#define FLG_ENABLE_EXCEPTION_LOGGING            0x00800000
#define FLG_ENABLE_HANDLE_TYPE_TAGGING          0x01000000
#define FLG_HEAP_PAGE_ALLOCS                    0x02000000
#define FLG_DEBUG_INITIAL_COMMAND_EX            0x04000000
#define FLG_VALID_BITS                          0x07FFFFFF


//static
//
//VOID
//NTAPI
//ExceptionRecord32To64(IN PEXCEPTION_RECORD32 Ex32,
//                      OUT PEXCEPTION_RECORD64 Ex64)
//{
//    ULONG i;
//
//    Ex64->ExceptionCode = Ex32->ExceptionCode;
//    Ex64->ExceptionFlags = Ex32->ExceptionFlags;
//    Ex64->ExceptionRecord = Ex32->ExceptionRecord;
//    COPYSE(Ex64,Ex32,ExceptionAddress);
//    Ex64->NumberParameters = Ex32->NumberParameters;
//
//    for (i = 0; i < EXCEPTION_MAXIMUM_PARAMETERS; i++)
//    {
//        COPYSE(Ex64,Ex32,ExceptionInformation[i]);
//    }
//}

#endif
