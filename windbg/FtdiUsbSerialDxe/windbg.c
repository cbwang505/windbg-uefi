#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SerialPortLib.h>
#include <Library/TimerLib.h>
#include "DebugAgent.h"
//
// Boot and Runtime Services
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>



#include "stdint.h"



#include "windbg.h"

#include <windbgkd.h>
#include <wdbgexts.h>
#include <ketypes.h>
#include <ke.h>
#include <rtlfuncs.h>
#include <intrin.h>

typedef enum {
	NativeCom,
	VmbusChannel,
	VmbusMirror
}VmbusWindbgProtocol;

VmbusWindbgProtocol gVmbusWindbgProtocol = VmbusChannel;
//VmbusWindbgProtocol gVmbusWindbgProtocol = NativeCom;


#define KD_SYMBOLS_MAX 0x100
#define EXCEPTION_EXECUTE_HANDLER 1

/* And reload the definitions with these new names */

//#include <kddll.h>


EFI_GUID gEfiWindbgProtocolGUID = { 0xd6ef2483,0xa5de,0x4fa4,{0x8b,0xc3,0x83,0x92,0x50,0xb6,0xff,0xfd} };

EFI_WINDBGPROTOCOL gWindbgProtocol = { 0 };

extern  DEBUG_MP_CONTEXT volatile  mDebugMpContext;

extern DEBUG_AGENT_MAILBOX       mMailbox;
extern DEBUG_AGENT_MAILBOX* mMailboxPointer;
extern IA32_IDT_GATE_DESCRIPTOR  mIdtEntryTable[33];
extern BOOLEAN                   mDxeCoreFlag;
extern BOOLEAN                   mMultiProcessorDebugSupport;
extern VOID* mSavedIdtTable;
extern UINTN                     mSaveIdtTableSize;
extern BOOLEAN                   mDebugAgentInitialized;
extern BOOLEAN                   mSkipBreakpoint;


UINT32 ExceptionStubHeaderSize = 0x13;
UINT32 ReplyreqCache[KD_SYMBOLS_MAX] = { 0 };
typedef struct _KD_SYMBOLS_MAP
{
	UINT64 BaseOfAddr;
	UINT64 MapOfAddr;
	ULONG SizeOfAddr;
} KD_SYMBOLS_MAP, * PKD_SYMBOLS_MAP;

#define ctxchgimpl(a,b,x,y) \
a->x = b->y

#define ctxchg(a,b,x,y,reverse) \
if(reverse==TRUE)\
{\
	ctxchgimpl(b, a, y,x);\
}else\
{\
	ctxchgimpl(a, b,x,y);\
}



#define ctxchg64to16(a,b,x,y,reverse) \
if(reverse==TRUE)\
{\
	ctxchgimpl(b, a, y,x);\
}else\
{\
	a->x = (UINT16)b->y;\
}

#define ctxchgsame(a,b,x,reverse) \
if(reverse==TRUE)\
{\
	ctxchgimpl(b, a, x, x);\
}else\
{\
	ctxchgimpl(a, b, x, x);\
}




#define CHECKASSERT(Expression,Text)\
if(Expression)\
{\
	Print(L"%s %s %s\r\n", __FILE__, __LINE__, Text);\
}
/* GLOBALS ********************************************************************/
//
// Buffers
//
CHAR KdpMessageBuffer[KDP_MSG_BUFFER_SIZE];
CHAR KdpPathBuffer[KDP_MSG_BUFFER_SIZE];
CHAR KdpPathAuxBuffer[KDP_MSG_BUFFER_SIZE];
CHAR KdpPathPrintBuffer[KDP_MSG_BUFFER_SIZE];
CHAR KdpPathSymbolBuffer[KDP_MSG_BUFFER_SIZE];
CHAR KdpPathSafeBuffer[KDP_MSG_BUFFER_SIZE];
BOOLEAN ForceConsoleOutput = FALSE;
BOOLEAN ForcePorteOutput = FALSE;
ULONG CurrentPacketId = INITIAL_PACKET_ID | SYNC_PACKET_ID;
ULONG RemotePacketId = INITIAL_PACKET_ID;
BOOLEAN KdpContextSent = FALSE;
BOOLEAN KdpContextSyncPacket = FALSE;
BOOLEAN KdDebuggerNotPresent = FALSE;
BOOLEAN VmbusServiceProtocolLoaded = FALSE;
BOOLEAN VmbusKdInitSystemLoaded = FALSE;
int ReportSynthetic = 0;
//
BOOLEAN KdBreakAfterSymbolLoad;
BOOLEAN KdPitchDebugger = FALSE;

BOOLEAN KdDebuggerEnabled = TRUE;
BOOLEAN KdAutoEnableOnEvent;
BOOLEAN KdBlockEnable;
BOOLEAN KdIgnoreUmExceptions;
BOOLEAN KdPreviouslyEnabled;
BOOLEAN KdpDebuggerStructuresInitialized;
BOOLEAN KdEnteredDebugger;
BOOLEAN KdpPortLocked;
KIRQL KdpNowKIRQL = PASSIVE_LEVEL;
ULONG KdDisableCount;
LARGE_INTEGER KdPerformanceCounterRate;

LONG KdpTimeSlipPending = 1;
PVOID KdpTimeSlipEvent;
//KSPIN_LOCK KdpTimeSlipEventLock;
LARGE_INTEGER KdTimerStop, KdTimerStart, KdTimerDifference;

//
BREAKPOINT_ENTRY KdpBreakpointTable[KD_BREAKPOINT_MAX];
KD_BREAKPOINT_TYPE KdpBreakpointInstruction = KD_BREAKPOINT_VALUE;
BOOLEAN KdpOweBreakpoint;
BOOLEAN BreakpointsSuspended;
BOOLEAN KdpControlCPressed;
/* NT System Info */
ULONG NtGlobalFlag = 0;
ULONG ExSuiteMask;
ULONG KdpNumInternalBreakpoints;
KD_CONTEXT KdpContext = { 0 };
//
// Symbol Data
//
ULONG_PTR KdpCurrentSymbolStart, KdpCurrentSymbolEnd;

// KdPrint Buffers
//
CHAR KdPrintDefaultCircularBuffer[KD_DEFAULT_LOG_BUFFER_SIZE];
PCHAR KdPrintWritePointer = KdPrintDefaultCircularBuffer;
ULONG KdPrintRolloverCount;
PCHAR KdPrintCircularBuffer = KdPrintDefaultCircularBuffer;
ULONG KdPrintBufferSize = sizeof(KdPrintDefaultCircularBuffer);
ULONG KdPrintBufferChanges = 0;


KIPCR gPcr = { 0 };
KPRCB gPrcb = { 0 };
UEFI_SYMBOLS_INFO mSyntheticSymbolInfo[KD_SYMBOLS_MAX] = { 0 };

PKD_PACKETEXTRA pPengdingManipulatePacket = NULL;
UINT32  FailedOperateMemoryCount = 0;
UINT64  FailedOperateMemoryAddress1 = 0;
UINT64  FailedOperateMemoryAddress2 = 0;
UINT64  FailedOperateMemoryAddressArray[KD_SYMBOLS_MAX] = { 0 };

KD_SYMBOLS_MAP gsymmap[KD_SYMBOLS_MAX] = { 0 };
static BOOLEAN termconfirmed = FALSE;

__declspec(align(VSM_PAGE_SIZE)) UINT8 vmbus_output_page[VSM_PAGE_SIZE_DOUBLE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 vmbus_input_page[VSM_PAGE_SIZE_DOUBLE];

volatile UINT32 vmbus_output_start = 0;

volatile UINT32 vmbus_input_start = 0;
volatile UINT32 vmbus_input_end = 0;
volatile UINT32 vmbus_input_len = 0;
//
// Debugger Version and Data Block
//
DBGKD_GET_VERSION64 KdVersionBlock =
{
	0xf,
	0x4a61,
	DBGKD_64BIT_PROTOCOL_VERSION2,
	KD_SECONDARY_VERSION_AMD64_CONTEXT,
	0x47,
	IMAGE_FILE_MACHINE_NATIVE,
	PACKET_TYPE_MAX,
	3,
	0x33,
	DBGKD_SIMULATION_NONE,
	{0},
	0,
	0,
	0
};

int vmbus_sendpacket_windbg(UINT32 vmbus_output_start,
	UINT32 vmbus_output_end);

int vmbus_receivepacket_windbg(void* buffer, UINT32 buflen, UINT32 buflennext, UINT32* buffer_actual_len, UINT32* replyreq);

EFI_STATUS NTAPI HvVmbusServiceDxeInitialize();
void NTAPI DumpRsp();
void NTAPI DumpRet(UINT64 addrsp);

VOID
NTAPI
KdpZeroMemory(
	_In_ PVOID Destination,
	_In_ UINT32 Length);
VOID
NTAPI
KdpMoveMemory(
	_In_ PVOID Destination,
	_In_ PVOID Source,
	_In_ UINT32 Length);
BOOLEAN NTAPI  HvMemoryReadPresent(UINT64 gva);
BOOLEAN NTAPI HvMemoryDump(UINT64 gva);
NTSTATUS
NTAPI
KdpCopyMemoryChunks(
	_In_ ULONG64 Address,
	_In_ PVOID Buffer,
	_In_ ULONG TotalSize,
	_In_ ULONG ChunkSize,
	_In_ ULONG Flags,
	_Out_opt_ PULONG ActualSize);
NTSTATUS
NTAPI
KdSave(
	IN BOOLEAN SleepTransition
);
NTSTATUS
NTAPI
KdRestore(
	IN BOOLEAN SleepTransition
);
NTSTATUS
NTAPI
KdpPrint(
	_In_ ULONG ComponentId,
	_In_ ULONG Level,
	_In_reads_bytes_(Length) PCHAR String,
	_In_ USHORT Length,
	_In_ KPROCESSOR_MODE PreviousMode,
	_In_ PKTRAP_FRAME TrapFrame,
	_In_ PKEXCEPTION_FRAME ExceptionFrame,
	_Out_ PBOOLEAN Handled);
VOID
FindAndReportModuleImageInfoWindbg(
	IN UINTN  AlignSize, PUEFI_SYMBOLS_INFO pSyntheticSymbolInfo
);
BOOLEAN
NTAPI
KdEnterDebugger(IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame);
VOID
NTAPI
KdExitDebugger(IN BOOLEAN Enable);
BOOLEAN KdInitSystem(IN EFI_HANDLE   ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable, ULONG BootPhase, void* LoaderBlock);
VOID
NTAPI
KdpSymbol(IN PSTRING DllPath,
	IN PKD_SYMBOLS_INFO SymbolInfo,
	IN BOOLEAN Unload,
	IN KPROCESSOR_MODE PreviousMode,
	IN PCONTEXT ContextRecord,
	IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame, DEBUG_CPU_CONTEXT* CpuContext, BOOLEAN sendonce);
VOID
NTAPI
KdpSendControlPacket(
	IN USHORT PacketType,
	IN ULONG PacketId OPTIONAL);
BOOLEAN
NTAPI
KdpPrintString(
	_In_ PSTRING Output);

int fakeidx = 0;
BOOLEAN CheckRingBuferrMemoryInput()
{
	UINT32  ring_buffer_size = VSM_PAGE_SIZE_DOUBLE;
	UINT32 availlen = 0;
	if (vmbus_input_start > ring_buffer_size || vmbus_input_end > ring_buffer_size)
	{
		Print(L"CheckRingBuferrMemoryInput overflow %08x %08x %08x %08x\r\n", vmbus_input_start, vmbus_input_end, vmbus_input_len, availlen);
		return FALSE;
	}
	if (vmbus_input_start == 0 && vmbus_input_end == 0)
	{
		availlen = 0;
	}
	else {
		if (vmbus_input_end > vmbus_input_start)
		{
			availlen = vmbus_input_end - vmbus_input_start;
		}
		else if (vmbus_input_end == vmbus_input_start && vmbus_input_len == 0)
		{
			availlen = 0;
		}
		else
		{
			availlen = vmbus_input_end + ring_buffer_size - vmbus_input_start;
		}
	}

	if (vmbus_input_len != availlen)
	{
		Print(L"CheckRingBuferrMemoryInput failed %08x %08x %08x %08x\r\n", vmbus_input_start, vmbus_input_end, vmbus_input_len, availlen);

		while (TRUE)
		{
			stall(0x1000);
		}
		return FALSE;

	}

	return TRUE;
}
BOOLEAN  CopyRingBuferrMemoryOutput(void* src,
	UINT32  srclen)
{
	BOOLEAN splitrinbuf = FALSE;
	UINT64 ring_buffer = (UINT64)(vmbus_output_page);
	UINT32  ring_buffer_size = VSM_PAGE_SIZE_DOUBLE;
	UINT32 start_write_offset = vmbus_output_start;

	if (start_write_offset + srclen > ring_buffer_size)
	{
		UINT32 FragSize = ring_buffer_size - start_write_offset;
		hvcopymemory((void*)(ring_buffer + start_write_offset), src, FragSize);
		UINT32 remainlength = srclen - FragSize;
		hvcopymemory((void*)(ring_buffer), (void*)((UINT64)src + FragSize), remainlength);
		splitrinbuf = TRUE;
	}
	else {
		hvcopymemory((void*)(ring_buffer + start_write_offset), src, srclen);
	}

	start_write_offset += srclen;
	if (start_write_offset >= ring_buffer_size)
		start_write_offset -= ring_buffer_size;
	vmbus_output_start = start_write_offset;

	return splitrinbuf;
}
VOID
NTAPI
ResetRingBuferInputToOrigin()
{
	UINT64 ring_buffer = (UINT64)(vmbus_input_page);
	UINT32  ring_buffer_size = VSM_PAGE_SIZE_DOUBLE;
	hvresetmemory((void*)ring_buffer, ring_buffer_size);
	vmbus_input_start = 0;
	vmbus_input_end = 0;
	vmbus_input_len = 0;
	return;
}

KDP_STATUS
NTAPI
CopyRingBuferrMemoryInputAvail(
	OUT UINT8* Buffer,
	IN  UINT32   NumberOfBytes)
{
	KDP_STATUS ret = KDP_PACKET_RESEND;
	UINT64 ring_buffer = (UINT64)(vmbus_input_page);
	CheckRingBuferrMemoryInput();
	if (vmbus_input_end > vmbus_input_start)
	{
		UINT32 availlen = vmbus_input_end - vmbus_input_start;
		if (availlen >= NumberOfBytes)
		{
			hvcopymemory(Buffer, (void*)(ring_buffer + vmbus_input_start), NumberOfBytes);
			vmbus_input_len -= NumberOfBytes;
			vmbus_input_start += NumberOfBytes;
			ret = KDP_PACKET_RECEIVED;
		}
		else
		{
			ret = KDP_PACKET_RESEND;
		}


	}
	else
	{
		ret = KDP_PACKET_RESEND;
	}
	CheckRingBuferrMemoryInput();
	return ret;
}
KDP_STATUS
NTAPI
CopyRingBuferrMemoryInputSplit(
	OUT UINT8* Buffer,
	IN  UINT32   NumberOfBytes)
{
	KDP_STATUS ret = KDP_PACKET_RESEND;
	UINT64 ring_buffer = (UINT64)(vmbus_input_page);
	UINT32  ring_buffer_size = VSM_PAGE_SIZE_DOUBLE;
	if (vmbus_input_end > vmbus_input_start)
	{
		UINT32 availlen = vmbus_input_end - vmbus_input_start;
		if (availlen >= NumberOfBytes)
		{
			ret = CopyRingBuferrMemoryInputAvail(Buffer, NumberOfBytes);
		}
		else
		{
			CheckRingBuferrMemoryInput();
			ret = KDP_PACKET_RESEND;
		}

	}
	else
	{
		CheckRingBuferrMemoryInput();

		UINT32 availlen = vmbus_input_end + ring_buffer_size - vmbus_input_start;
		if (availlen >= NumberOfBytes)
		{
			UINT32 FragSize = ring_buffer_size - vmbus_input_start;
			if (FragSize > NumberOfBytes)
			{
				hvcopymemory(Buffer, (void*)(ring_buffer + vmbus_input_start), NumberOfBytes);
				vmbus_input_start += NumberOfBytes;

			}
			else if (FragSize == NumberOfBytes)
			{
				hvcopymemory(Buffer, (void*)(ring_buffer + vmbus_input_start), FragSize);
				vmbus_input_start = 0;
			}
			else
			{


				hvcopymemory(Buffer, (void*)(ring_buffer + vmbus_input_start), FragSize);

				UINT32 remainlength = NumberOfBytes - FragSize;
				hvcopymemory((void*)(Buffer + FragSize), (void*)(ring_buffer), remainlength);
				vmbus_input_start = remainlength;

			}

			ret = KDP_PACKET_RECEIVED;
			vmbus_input_len -= NumberOfBytes;
		}
		else {

			ret = KDP_PACKET_RESEND;
		}
		CheckRingBuferrMemoryInput();
	}
	return ret;
}

BOOLEAN ChechReplyReqCache(IN  UINT32  PushSeq, IN  UINT32   WaiteSeq)
{
	BOOLEAN ret = FALSE;
	if (PushSeq == 0 && WaiteSeq == 0)
	{
		return FALSE;
	}
	if (PushSeq == WaiteSeq)
	{
		//Print(L"ChechReplyReqCache ok stack %08x\r\n", WaiteSeq);
		return TRUE;
	}
	if (PushSeq == 0)
	{
		for (int i = 0; i < KD_SYMBOLS_MAX; i++)
		{
			UINT32 replyreqtmp = ReplyreqCache[i];
			if (replyreqtmp != 0 && WaiteSeq != 0)
			{
				if (replyreqtmp == WaiteSeq)
				{
					ReplyreqCache[i] = 0;
					ret = TRUE;
					break;
				}
			}
		}
	}
	else
	{
		BOOLEAN pushed = FALSE;
		for (int i = 0; i < KD_SYMBOLS_MAX; i++)
		{
			UINT32 replyreqtmp = ReplyreqCache[i];
			if (replyreqtmp == 0)
			{
				if (!pushed)
				{

					ReplyreqCache[i] = PushSeq;
					pushed = TRUE;
					if (PushSeq != 0 && WaiteSeq == 0)
					{
						return pushed;
					}
					if (pushed && ret) {
						break;
					}
				}
			}
			else
			{
				if (WaiteSeq != 0)
				{
					if (replyreqtmp == WaiteSeq)
					{
						ReplyreqCache[i] = 0;
						ret = TRUE;
						if (pushed && ret) {
							break;
						}
					}
				}
			}
		}

		if (PushSeq != 0 && WaiteSeq == 0)
		{
			return pushed;
		}

	}

	if (ret)
	{
		Print(L"ChechReplyReqCache ok %08x\r\n", WaiteSeq);
	}
	return  ret;
}

KDP_STATUS
NTAPI
CopyRingBuferrMemoryInput(
	OUT UINT8* Buffer,
	IN  UINT32   NumberOfBytes, IN  UINT32   WaiteSeq)
{
	UINT32  ring_buffer_size = VSM_PAGE_SIZE_DOUBLE;
	UINT64 ring_buffer = (UINT64)(vmbus_input_page);
	UINT32 receivelen = 0;
	int failcount = 0;
	int gocount = 0;
	UINT32 replyreq = 0;
	BOOLEAN ContinueOnStack=TRUE;
	CheckRingBuferrMemoryInput();
	
	if (NumberOfBytes == 0 && WaiteSeq == 0 && Buffer == NULL)
	{

		Print(L"CopyRingBuferrMemoryInput overflow all zero \r\n");
	}
	if (WaiteSeq == 0)
	{
		if (NumberOfBytes == 0 || Buffer == NULL)
		{

			Print(L"CopyRingBuferrMemoryInput overflow all zero  %08x %p\r\n", NumberOfBytes, Buffer);

			return KDP_PACKET_TIMEOUT;
		}
		if (vmbus_input_end > vmbus_input_start)
		{
			UINT32 availlen = vmbus_input_end - vmbus_input_start;
			if (availlen >= NumberOfBytes)
			{
				return CopyRingBuferrMemoryInputAvail(Buffer, NumberOfBytes);
			}

		}
		else if (vmbus_input_len > 0)
		{
			UINT32 availlen = vmbus_input_end + ring_buffer_size - vmbus_input_start;

			if (availlen != vmbus_input_len)
			{
				Print(L"vmbus_receivepacket_windbg remain len chak part failed \r\n");
				while (TRUE)
				{
					stall(0x1000);
				}
				return KDP_PACKET_TIMEOUT;
			}
			if (availlen >= NumberOfBytes)
			{

				return CopyRingBuferrMemoryInputSplit(Buffer, NumberOfBytes);

			}
		}
	}
	else
	{

		if (ChechReplyReqCache(0, WaiteSeq))
		{
			return KDP_PACKET_RECEIVED;
		}


	}
	while (TRUE)
	{
		
		/*if (gocount > 10)
		{
			
			Print(L"vmbus_receivepacket_windbg gocount failed KDP_PACKET_TIMEOUT %08x %08x %08x %08x\r\n", vmbus_input_start, vmbus_input_end, NumberOfBytes, WaiteSeq);
			//ResetRingBuferInputToOrigin();
			while (TRUE)
			{
				stall(100);
			}
			return KDP_PACKET_RESEND;
		}*/
		if (vmbus_input_start == 0 && vmbus_input_end == 0)
		{
			//Print(L"fake failed %08x %08x %08x\r\n", vmbus_input_start, vmbus_input_end, vmbus_input_len);
			UINT32 remainlen = ring_buffer_size;
			UINT32 buffer_actual_len = 0;
			UINT8* bufferreceive = (UINT8*)(ring_buffer);
			receivelen = vmbus_receivepacket_windbg(bufferreceive, remainlen, 0, &buffer_actual_len, &replyreq);
			if (receivelen == 0)
			{
				
			
				failcount++;
				if (failcount > 1)
				{
					if (ContinueOnStack)
					{
						continue;
					}
					//ResetRingBuferInputToOrigin();
					return KDP_PACKET_TIMEOUT;
				}
				else
				{
					Print(L"vmbus_receivepacket_windbg KDP_PACKET_TIMEOUT\r\n");
					KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
					continue;
				}

			}

			//Print(L"fake failed %08x %08x %08x %08x\r\n", vmbus_input_start, vmbus_input_end, vmbus_input_len, buffer_actual_len);
			vmbus_input_end += buffer_actual_len;
			CheckRingBuferrMemoryInput();
			if (WaiteSeq == 0)
			{
				if (replyreq != 0)
				{
					ChechReplyReqCache(replyreq, 0);
				}
				//Print(L"fake failed %08x %08x %08x %08x\r\n", vmbus_input_start, vmbus_input_end, vmbus_input_len, buffer_actual_len);

				UINT32 availlen = vmbus_input_end - vmbus_input_start;
				if (availlen >= NumberOfBytes)
				{
					return CopyRingBuferrMemoryInputAvail(Buffer, NumberOfBytes);
				}
			}
			else
			{

				if (ChechReplyReqCache(replyreq, WaiteSeq))
				{
					return KDP_PACKET_RECEIVED;
				}
			}
			gocount++;
			continue;
		}
		else if (vmbus_input_end == vmbus_input_start)
		{
			//ResetRingBuferInputToOrigin();
			UINT32 remainlen = ring_buffer_size - vmbus_input_end;
			UINT32 buffer_actual_len = 0;
			UINT8* bufferreceive = (UINT8*)(ring_buffer + vmbus_input_end);
			UINT32 buflennext = vmbus_input_start;
			receivelen = vmbus_receivepacket_windbg(bufferreceive, remainlen, buflennext, &buffer_actual_len, &replyreq);
			if (receivelen == 0)
			{
				
				failcount++;
				
				if (failcount > 1)
				{
					if (ContinueOnStack)
					{
						continue;
					}
					//ResetRingBuferInputToOrigin();
					return KDP_PACKET_TIMEOUT;
				}
				else
				{
					Print(L"vmbus_receivepacket_windbg KDP_PACKET_TIMEOUT\r\n");
					KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
					continue;
				}
			}
			vmbus_input_end += buffer_actual_len;
			if (vmbus_input_end > ring_buffer_size)
			{
				vmbus_input_end -= ring_buffer_size;
			}
			CheckRingBuferrMemoryInput();

			if (WaiteSeq == 0)
			{
				if (replyreq != 0)
				{
					ChechReplyReqCache(replyreq, 0);
				}
				if (vmbus_input_end >= vmbus_input_start)
				{
					UINT32 availlen = vmbus_input_end - vmbus_input_start;
					if (availlen >= NumberOfBytes)
					{
						return CopyRingBuferrMemoryInputAvail(Buffer, NumberOfBytes);
					}
				}
				else
				{
					UINT32 availlen = vmbus_input_end + ring_buffer_size - vmbus_input_start;
					if (availlen >= NumberOfBytes)
					{

						return CopyRingBuferrMemoryInputSplit(Buffer, NumberOfBytes);

					}
				}
			}
			else
			{

				if (ChechReplyReqCache(replyreq, WaiteSeq))
				{
					return KDP_PACKET_RECEIVED;
				}
			}
			gocount++;
			continue;

		}
		else if (vmbus_input_end > vmbus_input_start)
		{

			//剩余缓冲区用完了从开头开始读
			UINT32 remainlen = ring_buffer_size - vmbus_input_end;
			if (remainlen > 0)
			{
				UINT32 buffer_actual_len = 0;
				UINT8* bufferreceive = (UINT8*)(ring_buffer + vmbus_input_end);
				UINT32 buflennext = vmbus_input_start;
				receivelen = vmbus_receivepacket_windbg(bufferreceive, remainlen, buflennext, &buffer_actual_len, &replyreq);
				if (receivelen == 0)
				{
					
					failcount++;
					if (failcount > 1)
					{
						if (ContinueOnStack)
						{
							continue;
						}
						//ResetRingBuferInputToOrigin();
						return KDP_PACKET_TIMEOUT;
					}
					else
					{
						Print(L"vmbus_receivepacket_windbg KDP_PACKET_TIMEOUT\r\n");
						KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
						continue;
					}
				}
				vmbus_input_end += buffer_actual_len;
				if (vmbus_input_end > ring_buffer_size)
				{
					vmbus_input_end -= ring_buffer_size;
				}
				CheckRingBuferrMemoryInput();
				if (WaiteSeq == 0)
				{
					if (replyreq != 0)
					{
						ChechReplyReqCache(replyreq, 0);
					}
					if (vmbus_input_end >= vmbus_input_start)
					{
						UINT32 availlen = vmbus_input_end - vmbus_input_start;
						if (availlen >= NumberOfBytes)
						{
							return CopyRingBuferrMemoryInputAvail(Buffer, NumberOfBytes);
						}
					}
					else
					{
						UINT32 availlen = vmbus_input_end + ring_buffer_size - vmbus_input_start;
						if (availlen >= NumberOfBytes)
						{

							return CopyRingBuferrMemoryInputSplit(Buffer, NumberOfBytes);

						}
					}
				}
				else
				{

					if (ChechReplyReqCache(replyreq, WaiteSeq))
					{
						return KDP_PACKET_RECEIVED;
					}
				}
				gocount++;
				continue;
			}
			else
			{
				remainlen = vmbus_input_start;
				UINT32 buffer_actual_len = 0;
				UINT8* bufferreceive = (UINT8*)(ring_buffer);
				receivelen = vmbus_receivepacket_windbg(bufferreceive, remainlen, 0, &buffer_actual_len, &replyreq);
				if (receivelen == 0)
				{
				
					failcount++;
					if (failcount > 1)
					{
						if (ContinueOnStack)
						{
							continue;
						}
						//ResetRingBuferInputToOrigin();
						return KDP_PACKET_TIMEOUT;
					}
					else
					{
						Print(L"vmbus_receivepacket_windbg KDP_PACKET_TIMEOUT\r\n");
						KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
						continue;
					}
				}
				vmbus_input_end = buffer_actual_len;
				CheckRingBuferrMemoryInput();
				if (WaiteSeq == 0)
				{
					if (replyreq != 0)
					{
						ChechReplyReqCache(replyreq, 0);
					}
					UINT32 availlen = vmbus_input_end + ring_buffer_size - vmbus_input_start;
					if (availlen >= NumberOfBytes)
					{

						return CopyRingBuferrMemoryInputSplit(Buffer, NumberOfBytes);

					}
				}
				else
				{

					if (ChechReplyReqCache(replyreq, WaiteSeq))
					{
						return KDP_PACKET_RECEIVED;
					}
				}
				//如果读取的还不够

				gocount++;
				continue;
			}
		}
		else
		{


			UINT32 remainlen = vmbus_input_start - vmbus_input_end;
			UINT32 buffer_actual_len = 0;
			UINT8* bufferreceive = (UINT8*)(ring_buffer)+vmbus_input_end;
			receivelen = vmbus_receivepacket_windbg(bufferreceive, remainlen, 0, &buffer_actual_len, &replyreq);
			if (receivelen == 0)
			{
				
				failcount++;
				if (failcount > 1)
				{
					if (ContinueOnStack)
					{
						continue;
					}
					//ResetRingBuferInputToOrigin();
					return KDP_PACKET_TIMEOUT;
				}
				else
				{
					Print(L"vmbus_receivepacket_windbg KDP_PACKET_TIMEOUT\r\n");
					KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
					continue;
				}
			}

			if (buffer_actual_len == remainlen)
			{
				Print(L"vmbus_receivepacket_windbg remain len all consumed \r\n");
				while (TRUE)
				{
					stall(0x1000);
				}
				return KDP_PACKET_TIMEOUT;
			}

			vmbus_input_end += buffer_actual_len;
			CheckRingBuferrMemoryInput();

			if (WaiteSeq == 0)
			{
				if (replyreq != 0)
				{
					ChechReplyReqCache(replyreq, 0);
				}
				UINT32 availlen = vmbus_input_end + ring_buffer_size - vmbus_input_start;
				if (availlen >= NumberOfBytes)
				{

					return CopyRingBuferrMemoryInputSplit(Buffer, NumberOfBytes);

				}
			}
			else
			{

				if (ChechReplyReqCache(replyreq, WaiteSeq))
				{
					return KDP_PACKET_RECEIVED;
				}
			}
			//如果读取的还不够
			gocount++;
			continue;
		}
	}



	return KDP_PACKET_TIMEOUT;

}

VOID
NTAPI
KdSendPacketVmbus(
	IN PKD_PACKET Packet,
	IN PSTRING MessageHeader,
	IN PSTRING MessageData,
	IN OUT PKD_CONTEXT KdContext)
{
	if (!VmbusServiceProtocolLoaded)
	{
		return;
	}
	UINT8 tailbyte = PACKET_TRAILING_BYTE;
	UINT32  PacketLen = sizeof(KD_PACKET);

	if (MessageHeader)
	{
		if (MessageHeader->Length > 0)
		{
			PacketLen += (MessageHeader->Length);
			PacketLen += 1;
		}
	}
	if (MessageData)
	{
		if (MessageData->Length > 0)
		{
			PacketLen += MessageData->Length;
		}
	}


	BOOLEAN splitrinbuf = FALSE;
	UINT32 vmbus_output_start_save = vmbus_output_start;

	splitrinbuf |= CopyRingBuferrMemoryOutput(Packet, sizeof(KD_PACKET));
	if (MessageHeader)
	{
		if (MessageHeader->Length > 0)
		{
			splitrinbuf |= CopyRingBuferrMemoryOutput(MessageHeader->Buffer, MessageHeader->Length);
		}
	}
	/* If we have message data, also send it */
	if (MessageData != NULL)
	{
		if (MessageData->Length > 0)
		{
			splitrinbuf |= CopyRingBuferrMemoryOutput(MessageData->Buffer, MessageData->Length);
		}
	}
	if (MessageHeader)
	{
		if (MessageHeader->Length > 0)
		{
			splitrinbuf |= CopyRingBuferrMemoryOutput(&tailbyte, 1);
		}
	}
	vmbus_sendpacket_windbg(vmbus_output_start_save, vmbus_output_start);

	//KdpDprintf(L"vmbus_sendpacket_windbg %08x  %08x \r\n", vmbus_output_start_save, vmbus_output_start);

	return;
}


VOID
NTAPI
KdpDprintf(
	_In_ CHAR16* FormatString,
	...)
{
	/*if(!ForcePorteOutput)
	{
		return;
	}*/
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

	if (!VmbusKdInitSystemLoaded)
	{
		Print(Buffer);
		return;
	}
	//Data.Length = AsciiStrSize(KdpMessageBuffer);
	//UnicodeStrToAsciiStrS(Buffer, KdpPathPrintBuffer, KD_SYMBOLS_MAX);
	String.Length = (USHORT)w2s(Buffer, KdpPathPrintBuffer);
	UINT64 lenchk = AsciiStrSize(KdpPathPrintBuffer);
	if (lenchk == 0)
	{
		return;
	}
	String.Buffer = KdpPathPrintBuffer;
	/* Send it to the debugger directly */
	KdpPrintString(&String);
	return;
}


BOOLEAN UefiMemoryCanFetchByType(EFI_MEMORY_TYPE Type)
{    //case EfiPersistentMemory:
		//case EfiConventionalMemory:
	switch (Type)
	{
	case EfiLoaderCode:
		//case EfiLoaderData:
	case EfiBootServicesCode:
		//case EfiBootServicesData:
	case EfiRuntimeServicesCode:
		//case EfiRuntimeServicesData:
	case EfiReservedMemoryType:
	{
		return TRUE;
	}
	default:
	{

		return FALSE;
	}

	}
	//return FALSE;
}
BOOLEAN LowCheckMemoryAddr(UINT64 addr)
{
	if (addr < 0x100000 || addr>0x100000000)
	{
		return FALSE;
	}
	return TRUE;
}

BOOLEAN UefiMemoryPresent(UINT64 StartingAddr, UINTN Size)
{
	EFI_MEMORY_DESCRIPTOR* MemoryMap;
	EFI_MEMORY_DESCRIPTOR* MemoryMapEntry;
	EFI_MEMORY_DESCRIPTOR* MemoryMapEnd;
	UINTN    MemoryMapSize;
	UINTN    MapKey;
	UINTN    DescriptorSize;
	UINT32   DescriptorVersion;
	//UINT64   CurrentData;
	//UINT8    Checksum;
	BOOLEAN  MemoryFound;
	EFI_STATUS                   Status;
	//
	// Get the EFI memory map.
	//
	MemoryMapSize = 0;
	MemoryMap = NULL;
	MemoryFound = FALSE;
	if (!LowCheckMemoryAddr(StartingAddr))
	{
		return FALSE;
	}
	Status = gBS->GetMemoryMap(
		&MemoryMapSize,
		MemoryMap,
		&MapKey,
		&DescriptorSize,
		&DescriptorVersion
	);
	ASSERT(Status == EFI_BUFFER_TOO_SMALL);
	do {
		MemoryMap = (EFI_MEMORY_DESCRIPTOR*)AllocatePool(MemoryMapSize);
		ASSERT(MemoryMap != NULL);
		Status = gBS->GetMemoryMap(
			&MemoryMapSize,
			MemoryMap,
			&MapKey,
			&DescriptorSize,
			&DescriptorVersion
		);
		if (EFI_ERROR(Status)) {
			FreePool(MemoryMap);
		}
	} while (Status == EFI_BUFFER_TOO_SMALL);

	ASSERT_EFI_ERROR(Status);

	MemoryMapEntry = MemoryMap;
	MemoryMapEnd = (EFI_MEMORY_DESCRIPTOR*)((UINT64)MemoryMap + MemoryMapSize);
	while ((UINTN)MemoryMapEntry < (UINTN)MemoryMapEnd) {
		if ((MemoryMapEntry->PhysicalStart <= StartingAddr) &&
			((MemoryMapEntry->PhysicalStart +
				MultU64x32(MemoryMapEntry->NumberOfPages, EFI_PAGE_SIZE))
				>= (StartingAddr + Size)))
		{
			if (ForceConsoleOutput)
			{
				if (mSyntheticSymbolInfo[1].SymbolInfo.BaseOfDll && StartingAddr > (UINT64)mSyntheticSymbolInfo[1].SymbolInfo.BaseOfDll && StartingAddr < ((UINT64)mSyntheticSymbolInfo[1].SymbolInfo.BaseOfDll + mSyntheticSymbolInfo[1].SymbolInfo.SizeOfImage))
				{
					UINT64 startval = MemoryMapEntry->PhysicalStart;
					UINT64 endval = MemoryMapEntry->PhysicalStart +
						MultU64x32(MemoryMapEntry->NumberOfPages, EFI_PAGE_SIZE);
					KdpDprintf(L"UefiMemoryPresent mSyntheticSymbolInfo StartingAddr % p start %p  end %p type %08x attr %08x size %08x ok\r\n", StartingAddr, startval, endval, MemoryMapEntry->Type, MemoryMapEntry->Attribute, MemoryMapSize);
				}
			}
			if ((UefiMemoryCanFetchByType((EFI_MEMORY_TYPE)MemoryMapEntry->Type) == TRUE))
			{
				MemoryFound = TRUE;
			}
			else
			{
				MemoryFound = FALSE;
			}

			break;
		}

		MemoryMapEntry = NEXT_MEMORY_DESCRIPTOR(MemoryMapEntry, DescriptorSize);
	}

	FreePool(MemoryMap);

	return MemoryFound;
}

BOOLEAN UefiMemoryDump(UINT64 StartingAddr, UINTN Size)

{
	EFI_MEMORY_DESCRIPTOR* MemoryMap;
	EFI_MEMORY_DESCRIPTOR* MemoryMapEntry;
	EFI_MEMORY_DESCRIPTOR* MemoryMapEnd;
	UINTN    MemoryMapSize;
	UINTN    MapKey;
	UINTN    DescriptorSize;
	UINT32   DescriptorVersion;
	//UINT64   CurrentData;
	//UINT8    Checksum;
	BOOLEAN  MemoryFound;
	EFI_STATUS                   Status;
	//
	// Get the EFI memory map.
	//
	MemoryMapSize = 0;
	MemoryMap = NULL;
	MemoryFound = FALSE;
	if (StartingAddr > 0x100000000)
	{
		KdpDprintf(L"UefiMemoryPresent exceed max addr 0x100000000 StartingAddr %p \r\n", StartingAddr);
		return FALSE;
	}
	Status = gBS->GetMemoryMap(
		&MemoryMapSize,
		MemoryMap,
		&MapKey,
		&DescriptorSize,
		&DescriptorVersion
	);
	ASSERT(Status == EFI_BUFFER_TOO_SMALL);
	do {
		MemoryMap = (EFI_MEMORY_DESCRIPTOR*)AllocatePool(MemoryMapSize);
		ASSERT(MemoryMap != NULL);
		Status = gBS->GetMemoryMap(
			&MemoryMapSize,
			MemoryMap,
			&MapKey,
			&DescriptorSize,
			&DescriptorVersion
		);
		if (EFI_ERROR(Status)) {
			FreePool(MemoryMap);
		}
	} while (Status == EFI_BUFFER_TOO_SMALL);

	ASSERT_EFI_ERROR(Status);

	MemoryMapEntry = MemoryMap;
	MemoryMapEnd = (EFI_MEMORY_DESCRIPTOR*)((UINT64)MemoryMap + MemoryMapSize);
	while ((UINTN)MemoryMapEntry < (UINTN)MemoryMapEnd) {
		if ((MemoryMapEntry->PhysicalStart <= StartingAddr) &&
			((MemoryMapEntry->PhysicalStart +
				MultU64x32(MemoryMapEntry->NumberOfPages, EFI_PAGE_SIZE))
				>= (StartingAddr + Size)))
		{

			UINT64 startval = MemoryMapEntry->PhysicalStart;
			UINT64 endval = MemoryMapEntry->PhysicalStart +
				MultU64x32(MemoryMapEntry->NumberOfPages, EFI_PAGE_SIZE);
			KdpDprintf(L"UefiMemoryDump StartingAddr % p start %p end %p type %08x attr %08x size %08x ok\r\n", StartingAddr, startval, endval, MemoryMapEntry->Type, MemoryMapEntry->Attribute, MemoryMapSize);

			if ((UefiMemoryCanFetchByType((EFI_MEMORY_TYPE)MemoryMapEntry->Type) == TRUE))
			{
				MemoryFound = TRUE;
			}
			else
			{
				MemoryFound = FALSE;
			}

			break;
		}

		MemoryMapEntry = NEXT_MEMORY_DESCRIPTOR(MemoryMapEntry, DescriptorSize);
	}

	FreePool(MemoryMap);

	return MemoryFound;
}

UINTN
EFIAPI
SerialPortWritePipe(
	IN UINT8* Buffer,
	IN UINTN     NumberOfBytes
)
{
	DEBUG_PORT_HANDLE    Handle = GetDebugPortHandle();
	UINTN Index = 0;
	while (Index < NumberOfBytes) {

		DebugPortWriteBuffer(Handle, Buffer + Index, 1);
		Index++;
		continue;

	}

	return NumberOfBytes;
}


/**
  Read data from serial device and save the datas in buffer.

  Reads NumberOfBytes data bytes from a serial device into the buffer
  specified by Buffer. The number of bytes actually read is returned.
  If the return value is less than NumberOfBytes, then the rest operation failed.
  If Buffer is NULL, then ASSERT().
  If NumberOfBytes is zero, then return 0.

  @param  Buffer           Pointer to the data buffer to store the data read from the serial device.
  @param  NumberOfBytes    Number of bytes which will be read.

  @retval 0                Read data failed, no data is to be read.
  @retval >0               Actual number of bytes read from serial device.

**/
KDP_STATUS
EFIAPI
SerialPortReadPipeAsync(
	OUT UINT8* Buffer,
	IN  UINTN   NumberOfBytes
)
{
	BOOLEAN firstbyteread = FALSE;
	UINT32 failcount = 0;
	UINTN Index = 0;
	if (NumberOfBytes > 0)
	{
		DEBUG_PORT_HANDLE    Handle = GetDebugPortHandle();

		while (Index < NumberOfBytes) {
			if (DebugPortPollBuffer(Handle)) {
				DebugPortReadBuffer(Handle, Buffer + Index, 1, 0);
				firstbyteread = TRUE;
				Index++;
				continue;
			}
			else if (firstbyteread == TRUE)
			{
				if (NumberOfBytes == 1)
				{
					return KDP_PACKET_RECEIVED;
				}
				if (failcount > 500)
				{
					KdpDprintf(L"exit TimerCommand firstbytereadsecond async\r\n");
					return 	KDP_PACKET_TIMEOUT;
				}
				stall(5);
				failcount++;
				continue;
			}
			else
			{
				if (failcount > 10)
				{
					return 	KDP_PACKET_TIMEOUT;
				}
				failcount++;
				stall(10);
				continue;
			}

		}
	}
	return Index == NumberOfBytes ? KDP_PACKET_RECEIVED : KDP_PACKET_TIMEOUT;
}

KDP_STATUS
EFIAPI
SerialPortReadPipeSync(
	OUT UINT8* Buffer,
	IN  UINTN   NumberOfBytes
)
{
	UINTN Index = 0;
	if (NumberOfBytes > 0)
	{
		DEBUG_PORT_HANDLE    Handle = GetDebugPortHandle();

		while (Index < NumberOfBytes) {
			if (DebugPortPollBuffer(Handle)) {
				DebugPortReadBuffer(Handle, Buffer + Index, 1, 0);
				Index++;
				continue;
			}
			else
			{
				continue;
			}

		}
	}
	return Index == NumberOfBytes ? KDP_PACKET_RECEIVED : KDP_PACKET_TIMEOUT;
}


KDP_STATUS
EFIAPI
SerialPortReadPipeSync1(
	OUT UINT8* Buffer,
	IN  UINTN   NumberOfBytes
)
{
	BOOLEAN firstbyteread = FALSE;
	BOOLEAN firstbytereadsecond = FALSE;
	UINT32 failcount = 0;
	UINTN Index = 0;
	if (NumberOfBytes > 0)
	{
		DEBUG_PORT_HANDLE    Handle = GetDebugPortHandle();

		while (Index < NumberOfBytes) {
			if (DebugPortPollBuffer(Handle)) {
				DebugPortReadBuffer(Handle, Buffer + Index, 1, 0);
				firstbyteread = TRUE;
				firstbytereadsecond = TRUE;
				Index++;
				continue;
			}
			else if (firstbyteread == TRUE)
			{
				if (NumberOfBytes == 1)
				{
					return KDP_PACKET_RECEIVED;
				}
				continue;

			}
			else if (firstbytereadsecond == FALSE)
			{
				if (failcount > 500)
				{
					KdpDprintf(L"exit TimerCommand firstbytereadsecond\r\n");
					return 	KDP_PACKET_TIMEOUT;
				}
				stall(2);
				failcount++;
				continue;

			}
			else
			{
				if (failcount > 100)
				{
					KdpDprintf(L"exit TimerCommand\r\n");
					return 	KDP_PACKET_TIMEOUT;
				}
				failcount += 10;
				stall(10);
				continue;
			}

		}
	}
	return Index == NumberOfBytes ? KDP_PACKET_RECEIVED : KDP_PACKET_TIMEOUT;
}


KDP_STATUS
EFIAPI
SerialPortReadPipe(
	OUT UINT8* Buffer,
	IN  UINTN   NumberOfBytes
)
{

	return SerialPortReadPipeSync(Buffer, NumberOfBytes);
}


BOOLEAN
NTAPI
KdPollBreakIn(VOID);

KDP_STATUS
NTAPI
KdpReceivePacketLeader(
	OUT PULONG PacketLeader);

VOID
NTAPI
KdpSendByte(IN UCHAR Byte);

KDP_STATUS
NTAPI
KdpPollByte(OUT PUCHAR OutByte);

KDP_STATUS
NTAPI
KdpReceiveByte(OUT PUCHAR OutByte);

KDP_STATUS
NTAPI
KdpPollBreakIn(VOID);



KDP_STATUS
NTAPI
KdReceivePacket(
	IN ULONG PacketType,
	OUT PSTRING MessageHeader,
	OUT PSTRING MessageData,
	OUT PULONG DataLength,
	IN OUT PKD_CONTEXT Context

);
KDP_STATUS
NTAPI
KdSendPacket(
	IN ULONG PacketType,
	IN PSTRING MessageHeader,
	IN PSTRING MessageData,
	IN OUT PKD_CONTEXT Context
);
ULONG
NTAPI
KdpCalculateChecksum(
	IN PVOID Buffer,
	IN ULONG Length)
{
	PUCHAR ByteBuffer = Buffer;
	ULONG Checksum = 0;

	while (Length-- > 0)
	{
		Checksum += (ULONG)*ByteBuffer++;
	}
	return Checksum;
}


VOID
NTAPI
UefiCtx2WindbgCtxImpl(PDEBUG_CPU_CONTEXT pUefiCtx, PCONTEXT pWindbgCtx, BOOLEAN reverse)
{

	ctxchgsame(pWindbgCtx, pUefiCtx, Rax, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Rbx, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Rcx, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Rdx, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Rsi, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Rdi, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Rbp, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Rsp, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, R8, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, R9, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, R10, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, R11, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, R12, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, R13, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, R14, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, R15, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Dr0, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Dr1, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Dr2, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Dr3, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Dr6, reverse);
	ctxchgsame(pWindbgCtx, pUefiCtx, Dr7, reverse);
	if (reverse == FALSE)
	{
		ctxchg(pWindbgCtx, pUefiCtx, Rip, Eip, reverse);
	}

	if (reverse == FALSE)
	{
		pWindbgCtx->EFlags = ((ULONG)pUefiCtx->Eflags);

	}
	else
	{
		//pUefiCtx->Eflags = pWindbgCtx->EFlags;
	}
	ctxchg64to16(pWindbgCtx, pUefiCtx, SegGs, Gs, reverse);
	ctxchg64to16(pWindbgCtx, pUefiCtx, SegFs, Fs, reverse);
	ctxchg64to16(pWindbgCtx, pUefiCtx, SegEs, Es, reverse);
	ctxchg64to16(pWindbgCtx, pUefiCtx, SegDs, Ds, reverse);
	ctxchg64to16(pWindbgCtx, pUefiCtx, SegCs, Cs, reverse);
	ctxchg64to16(pWindbgCtx, pUefiCtx, SegSs, Ss, reverse);

	return;

}
VOID
NTAPI
UefiCtx2WindbgSpecialRegistersCtxImpl(PDEBUG_CPU_CONTEXT pUefiCtx, PKSPECIAL_REGISTERS pWindbgSpecialRegistersCtx, BOOLEAN reverse)
{
	ctxchgsame(pWindbgSpecialRegistersCtx, pUefiCtx, Cr0, reverse);
	ctxchgsame(pWindbgSpecialRegistersCtx, pUefiCtx, Cr2, reverse);
	ctxchgsame(pWindbgSpecialRegistersCtx, pUefiCtx, Cr3, reverse);
	ctxchgsame(pWindbgSpecialRegistersCtx, pUefiCtx, Cr4, reverse);
	ctxchgsame(pWindbgSpecialRegistersCtx, pUefiCtx, Cr8, reverse);
	ctxchg(pWindbgSpecialRegistersCtx, pUefiCtx, KernelDr0, Dr0, reverse);
	ctxchg(pWindbgSpecialRegistersCtx, pUefiCtx, KernelDr1, Dr1, reverse);
	ctxchg(pWindbgSpecialRegistersCtx, pUefiCtx, KernelDr2, Dr2, reverse);
	ctxchg(pWindbgSpecialRegistersCtx, pUefiCtx, KernelDr3, Dr3, reverse);
	ctxchg(pWindbgSpecialRegistersCtx, pUefiCtx, KernelDr6, Dr6, reverse);
	ctxchg(pWindbgSpecialRegistersCtx, pUefiCtx, KernelDr7, Dr7, reverse);
	if (reverse == FALSE)
	{
		//KdpMoveMemory(&pWindbgSpecialRegistersCtx->Gdtr, pUefiCtx->Gdtr, 0x10);


		AsmReadGdtr((IA32_DESCRIPTOR*)&pWindbgSpecialRegistersCtx->Gdtr.Limit);
	}
	else
	{
		KdpMoveMemory(pUefiCtx->Gdtr, &pWindbgSpecialRegistersCtx->Gdtr, 0x10);
	}
	if (reverse == FALSE)
	{
		//KdpMoveMemory(&pWindbgSpecialRegistersCtx->Idtr, pUefiCtx->Idtr, 0x10);
		AsmReadIdtr((IA32_DESCRIPTOR*)&pWindbgSpecialRegistersCtx->Idtr.Limit);
	}
	else
	{
		KdpMoveMemory(pUefiCtx->Idtr, &pWindbgSpecialRegistersCtx->Idtr, 0x10);
	}
	ctxchg64to16(pWindbgSpecialRegistersCtx, pUefiCtx, Tr, Tr, reverse);
	return;
}

VOID
NTAPI
UefiCtx2WindbgCtx(PDEBUG_CPU_CONTEXT pUefiCtx, PCONTEXT pWindbgCtx)
{
	UefiCtx2WindbgCtxImpl(pUefiCtx, pWindbgCtx, FALSE);
	return;
}
VOID
NTAPI
UefiCtx2WindbgSpecialRegistersCtx(PDEBUG_CPU_CONTEXT pUefiCtx, PKSPECIAL_REGISTERS pWindbgSpecialRegistersCtx)
{
	UefiCtx2WindbgSpecialRegistersCtxImpl(pUefiCtx, pWindbgSpecialRegistersCtx, FALSE);
	return;
}
VOID
NTAPI
WindbgSpecialRegistersCtx2UefiCtx(PKSPECIAL_REGISTERS pWindbgSpecialRegistersCtx, PDEBUG_CPU_CONTEXT pUefiCtx)
{
	UefiCtx2WindbgSpecialRegistersCtxImpl(pUefiCtx, pWindbgSpecialRegistersCtx, TRUE);
	return;
}
VOID
NTAPI
WindbgCtx2UefiCtx(PCONTEXT pWindbgCtx, PDEBUG_CPU_CONTEXT pUefiCtx)
{
	UefiCtx2WindbgCtxImpl(pUefiCtx, pWindbgCtx, TRUE);
	return;
}
NTSTATUS
NTAPI
KdpAllowDisable(VOID)
{

	return STATUS_ACCESS_DENIED;
}

NTSTATUS
NTAPI
KdpSysCheckLowMemory(IN ULONG Flags)
{

	return STATUS_UNSUCCESSFUL;
}

VOID
NTAPI
KeRaiseIrql(KIRQL a, PKIRQL b)
{
	*b = KdpNowKIRQL;
	KdpNowKIRQL = a;
	return;
}
VOID
NTAPI
KeLowerIrql(
	_In_ _IRQL_restores_ _Notliteral_ KIRQL NewIrql)
{
	KdpNowKIRQL = NewIrql;
	return;
}

UINT64
NTAPI
KeQueryPerformanceCounter(
	PLARGE_INTEGER PerformanceFrequency)
{
	UINT64 valret = GetPerformanceCounter();
	if (PerformanceFrequency)
	{
		(*PerformanceFrequency).QuadPart = valret;
	}
	return valret;
}

VOID
NTAPI
KdpPortLock(VOID)
{
	/* Acquire the lock */
	AcquireMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
	KdpPortLocked = TRUE;
	return;
}

VOID
NTAPI
KdpPortUnlock(VOID)
{
	/* Release the lock */
	ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
	KdpPortLocked = FALSE;
	return;
}
/**
  Execute Stepping command.

  @param[in] CpuContext        Pointer to saved CPU context.

**/
VOID
CommandStepping(
	IN DEBUG_CPU_CONTEXT* CpuContext
)
{
	IA32_EFLAGS32* Eflags;

	Eflags = (IA32_EFLAGS32*)&CpuContext->Eflags;
	Eflags->Bits.TF = 1;
	Eflags->Bits.RF = 1;
	//
	// Save and clear EFLAGS.IF to avoid interrupt happen when executing Stepping
	//
	SetDebugFlag(DEBUG_AGENT_FLAG_INTERRUPT_FLAG, Eflags->Bits.IF);
	Eflags->Bits.IF = 0;
	//
	// Set Stepping Flag
	//
	SetDebugFlag(DEBUG_AGENT_FLAG_STEPPING, 1);


	return;
}

/**
  Do some cleanup after Stepping command done.

  @param[in] CpuContext        Pointer to saved CPU context.

**/
VOID
CommandSteppingCleanup(
	IN DEBUG_CPU_CONTEXT* CpuContext
)
{
	IA32_EFLAGS32* Eflags;

	Eflags = (IA32_EFLAGS32*)&CpuContext->Eflags;
	Eflags->Bits.TF = 0;
	Eflags->Bits.RF = 0;
	//
	// Restore EFLAGS.IF
	//
	Eflags->Bits.IF = GetDebugFlag(DEBUG_AGENT_FLAG_INTERRUPT_FLAG);
	//Eflags->Bits.IF = 0;
	//
	// Clear Stepping flag
	//
	SetDebugFlag(DEBUG_AGENT_FLAG_STEPPING, 0);
	return;
}
NTSTATUS
NTAPI
KdpSysReadMsr(IN ULONG Msr,
	OUT PLARGE_INTEGER MsrValue)
{
	/* Use SEH to protect from invalid MSRs */

	MsrValue->QuadPart = __readmsr(Msr);


	return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdpSysWriteMsr(IN ULONG Msr,
	IN PLARGE_INTEGER MsrValue)
{

	__writemsr(Msr, MsrValue->QuadPart);


	return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
KdpSysReadIoSpace(IN ULONG InterfaceType,
	IN ULONG BusNumber,
	IN ULONG AddressSpace,
	IN ULONG64 IoAddress,
	OUT PVOID DataValue,
	IN ULONG DataSize,
	OUT PULONG ActualDataSize)
{
	/*/* Verify parameters #1#
	if (InterfaceType != Isa || BusNumber != 0 || AddressSpace != 1)
	{
		/* No data was read #1#
		*ActualDataSize = 0;
		return STATUS_INVALID_PARAMETER;
	}

	/* Check for correct alignment #1#
	if ((IoAddress & (DataSize - 1)))
	{
		/* Invalid alignment #1#
		*ActualDataSize = 0;
		return STATUS_DATATYPE_MISALIGNMENT;
	}
	*/

	switch (DataSize)
	{
		case sizeof(UCHAR) :
			/* Read one UCHAR */
			*(PUCHAR)DataValue = (UCHAR)(IoRead8((ULONG64)IoAddress));
			break;

			case sizeof(USHORT) :
				/* Read one USHORT */
				*(PUSHORT)DataValue = IoRead16((ULONG64)IoAddress);
				break;

				case sizeof(ULONG) :
					/* Read one ULONG */
					*(PULONG)DataValue = IoRead32((ULONG64)IoAddress);
					break;

				default:
					/* Invalid data size */
					*ActualDataSize = 0;
					return STATUS_INVALID_PARAMETER;
	}

	/* Return the size of the data */
	*ActualDataSize = DataSize;

	/* Success! */
	return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdpSysWriteIoSpace(IN ULONG InterfaceType,
	IN ULONG BusNumber,
	IN ULONG AddressSpace,
	IN ULONG64 IoAddress,
	IN PVOID DataValue,
	IN ULONG DataSize,
	OUT PULONG ActualDataSize)
{/*
	/* Verify parameters #1#
	if (InterfaceType != Isa || BusNumber != 0 || AddressSpace != 1)
	{
		/* No data was written #1#
		*ActualDataSize = 0;
		return STATUS_INVALID_PARAMETER;
	}

	/* Check for correct alignment #1#
	if ((IoAddress & (DataSize - 1)))
	{
		/* Invalid alignment #1#
		*ActualDataSize = 0;
		return STATUS_DATATYPE_MISALIGNMENT;
	}*/

	switch (DataSize)
	{
		case sizeof(UCHAR) :
			/* Write one UCHAR */
			IoWrite8((ULONG64)IoAddress, *(PUCHAR)DataValue);
			break;

			case sizeof(USHORT) :
				/* Write one USHORT */
				IoWrite16((ULONG64)IoAddress, *(PUSHORT)DataValue);
				break;

				case sizeof(ULONG) :
					/* Write one ULONG */
					IoWrite32((ULONG64)IoAddress, *(UINT32*)DataValue);
					break;

				default:
					/* Invalid data size */
					*ActualDataSize = 0;
					return STATUS_INVALID_PARAMETER;
	}

	/* Return the size of the data */
	*ActualDataSize = DataSize;

	/* Success! */
	return STATUS_SUCCESS;
}


KDP_STATUS
NTAPI
KdpReceiveBuffer(
	OUT PVOID Buffer,
	IN  ULONG Size)
{
	if (Size > 0)
	{
		if (gVmbusWindbgProtocol == NativeCom)
		{
			return  SerialPortReadPipe((UINT8*)Buffer, (UINTN)Size);
		}
		else
		{
			KDP_STATUS ret = CopyRingBuferrMemoryInput((UINT8*)Buffer, (UINTN)Size, 0);
			if (ret == KDP_PACKET_TIMEOUT)
			{
				KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
			}
			return ret;
		}
	}
	else
	{
		return KDP_PACKET_RECEIVED;
	}
}


KDP_STATUS
NTAPI
KdpReceiveBufferAsync(
	OUT PVOID Buffer,
	IN  ULONG Size)
{
	if (Size > 0)
	{

		return  SerialPortReadPipeAsync((UINT8*)Buffer, (UINTN)Size);

	}
	else
	{
		return KDP_PACKET_RECEIVED;
	}
}
UINT32
NTAPI
KeGetCurrentThread()
{
	return GetApicId() + 1;
}
VOID
NTAPI
KdpSetContextState(IN PDBGKD_ANY_WAIT_STATE_CHANGE WaitStateChange,
	IN PCONTEXT Context)
{
	WaitStateChange->u1.ControlReport.Dr6 = Context->Dr6;

	WaitStateChange->u1.ControlReport.Dr7 = Context->Dr7;


	/* Copy i386 specific segments */
	WaitStateChange->u1.ControlReport.SegCs = (USHORT)Context->SegCs;
	WaitStateChange->u1.ControlReport.SegDs = (USHORT)Context->SegDs;
	WaitStateChange->u1.ControlReport.SegEs = (USHORT)Context->SegEs;
	WaitStateChange->u1.ControlReport.SegFs = (USHORT)Context->SegFs;

	/* Copy EFlags */
	WaitStateChange->u1.ControlReport.EFlags = Context->EFlags;

	/* Set Report Flags */
	WaitStateChange->u1.ControlReport.ReportFlags = REPORT_INCLUDES_SEGS;
	if (WaitStateChange->u1.ControlReport.SegCs == KGDT64_R0_CODE)
	{
		WaitStateChange->u1.ControlReport.ReportFlags |= REPORT_STANDARD_CS;
	}
	return;
}
VOID
NTAPI
KdpSendBuffer(
	IN PVOID Buffer,
	IN ULONG Size)
{

	if (Size > 0)
	{
		SerialPortWritePipe((UINT8*)Buffer, (UINTN)Size);
	}
	return;
}
VOID
NTAPI
KdpSendByte(IN UCHAR Byte)
{

	SerialPortWritePipe((UINT8*)&Byte, 1);

	return;
}
KDP_STATUS
NTAPI
KdpReceiveByteAsync(OUT PUCHAR OutByte)
{
	return  SerialPortReadPipeAsync(OutByte, 1);
}
KDP_STATUS
NTAPI
KdpReceiveByte(OUT PUCHAR OutByte)
{
	return  KdpReceiveBuffer(OutByte, 1);
}
KDP_STATUS
NTAPI
KdpReceiveByteToTerminable()
{
	DEBUG_PORT_HANDLE    Handle = GetDebugPortHandle();
	KDP_STATUS ret = KDP_PACKET_RECEIVED;
	UCHAR termbyte = 0;
	int fidack = 0;
	while (ret == KDP_PACKET_RECEIVED)
	{
		if (DebugPortPollBuffer(Handle)) {
			ret = KdpReceiveBuffer(&termbyte, 1);
			if (termbyte == PACKET_TRAILING_BYTE)
			{
				ret = KDP_PACKET_RECEIVED;
				return ret;
				break;
			}
			else if (termbyte == CONTROL_PACKET_LEADER_BYTE)
			{
				fidack++;

			}
			else if (fidack > 1 && termbyte == 4)
			{
				KdpDprintf(L"fidack\r\n");
				ret = KdpReceiveBuffer(&termbyte, 0xb);

				return ret;
			}
		}
		else
		{
			continue;
		}
	}

	return ret;

}
KDP_STATUS
NTAPI
KdpReceiveByteToTerminableByte()
{
	DEBUG_PORT_HANDLE    Handle = GetDebugPortHandle();
	KDP_STATUS ret = KDP_PACKET_RECEIVED;
	UCHAR termbyte = 0;
	while (ret == KDP_PACKET_RECEIVED)
	{
		if (gVmbusWindbgProtocol == NativeCom)
		{
			if (DebugPortPollBuffer(Handle)) {
				ret = KdpReceiveBuffer(&termbyte, 1);
				if (termbyte == PACKET_TRAILING_BYTE)
				{
					ret = KDP_PACKET_RECEIVED;
					return ret;
					break;
				}
				else
				{
					continue;
				}
			}
		}
		else
		{
			ret = KdpReceiveBuffer(&termbyte, 1);
			if (termbyte == PACKET_TRAILING_BYTE)
			{
				ret = KDP_PACKET_RECEIVED;
				return ret;
				break;
			}
			else
			{
				continue;
			}
		}

	}

	return ret;
}

BOOLEAN
NTAPI
IntegralityCheckgManipulatePacketPromise(IN PKD_PACKETEXTRA PendingPacket)
{
	if (PendingPacket->Packet.PacketLeader == PACKET_LEADER && PendingPacket->Packet.PacketType == PACKET_TYPE_KD_STATE_MANIPULATE && PendingPacket->MessageHeader.Buffer != NULL)
	{
		PDBGKD_MANIPULATE_STATE64 pManipulateState = (PDBGKD_MANIPULATE_STATE64)(PendingPacket->MessageHeader.Buffer);

		if (!pManipulateState)
		{
			return FALSE;
		}


		if (!(pManipulateState->ApiNumber >= DbgKdApiMin && pManipulateState->ApiNumber <= DbgKdApiMax))
		{
			return FALSE;
		}

		if (pManipulateState->ApiNumber == DbgKdGetContextExApi)
		{
			PDBGKD_CONTEXT_EX ContextEx = &pManipulateState->u.ContextEx;
			if (ContextEx->Offset > KDP_MSG_BUFFER_SIZE || ContextEx->ByteCount > KDP_MSG_BUFFER_SIZE)
			{

				return FALSE;

			}
		}
		else if (pManipulateState->ApiNumber == DbgKdReadVirtualMemoryApi)
		{
			PDBGKD_READ_MEMORY64 ReadMemory = &pManipulateState->u.ReadMemory;
			if (ReadMemory->TransferCount == 0 || ReadMemory->ActualBytesRead != 0 || pManipulateState->ReturnStatus != 0)
			{
				if (ForceConsoleOutput)
				{
					dumpbuf(PendingPacket->MessageHeader.Buffer, PendingPacket->MessageHeader.Length & 0xf0);
				}

				return FALSE;
			}
			else
			{

				PendingPacket->MessageData.MaximumLength = KDP_MSG_BUFFER_SIZE;
				if (PendingPacket->MessageData.Buffer == NULL)
				{
					PendingPacket->MessageData.Buffer = AllocateZeroPool(PendingPacket->MessageData.MaximumLength);
				}
			}
		}

	}
	else if (PendingPacket->Packet.PacketLeader != CONTROL_PACKET_LEADER && PendingPacket->MessageHeader.Buffer == NULL)
	{
		return FALSE;
	}

	return TRUE;
}

PKD_PACKETEXTRA
NTAPI
EatPendingManipulatePacketPromise(IN ULONG ExpectPacketType)
{

	KDP_STATUS KdStatus = KDP_PACKET_RECEIVED;
	PKD_PACKETEXTRA PendingPacket = (PKD_PACKETEXTRA)AllocateZeroPool(sizeof(KD_PACKETEXTRA));
	termconfirmed = FALSE;
	BOOLEAN  DangleAcknowledgePacket = FALSE;
RetryReceivePacket:
	if (termconfirmed)
	{
		KdpDprintf(L"lost termconfirmed\r\n");
	}
	KdStatus = KdpReceivePacketLeader(&PendingPacket->Packet.PacketLeader);
	if (KdStatus != KDP_PACKET_RECEIVED)
	{
		/* Check if we got a breakin  */
		if (KdStatus == KDP_PACKET_RESEND)
		{
			KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
			goto RetryReceivePacket;
			//KdContext->KdpControlCPending = TRUE;
		}
		return NULL;
	}


	if (PendingPacket->Packet.PacketLeader != PACKET_LEADER &&
		PendingPacket->Packet.PacketLeader != CONTROL_PACKET_LEADER)
	{
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		goto RetryReceivePacket;
		//return KDP_PACKET_RESEND;
	}
	/* Step 2 - Read PacketType */
	KdStatus = KdpReceiveBuffer(&PendingPacket->Packet.PacketType, sizeof(USHORT));
	if (KdStatus != KDP_PACKET_RECEIVED)
	{
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		/* Didn't receive a PacketType. */
		goto RetryReceivePacket;
	}
	if (PendingPacket->Packet.PacketType == PACKET_TYPE_KD_POLL_BREAKIN)
	{
		return PendingPacket;
	}

	/* Check if we got a resend packet */
	if (PendingPacket->Packet.PacketLeader == CONTROL_PACKET_LEADER &&
		PendingPacket->Packet.PacketType == PACKET_TYPE_KD_RESEND)
	{
		//KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		;// goto RetryReceivePacket;
		//return KDP_PACKET_RESEND;

		return NULL;
	}

	/* Step 3 - Read ByteCount */
	KdStatus = KdpReceiveBuffer(&PendingPacket->Packet.ByteCount, sizeof(USHORT));
	if (KdStatus != KDP_PACKET_RECEIVED)
	{
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		/* Didn't receive ByteCount. */
		goto RetryReceivePacket;
	}

	if (PendingPacket->Packet.ByteCount > PACKET_MAX_SIZE)
	{
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		/* Didn't receive ByteCount. */
		goto RetryReceivePacket;
	}
	/* Step 4 - Read PacketId */
	KdStatus = KdpReceiveBuffer(&PendingPacket->Packet.PacketId, sizeof(ULONG));
	if (KdStatus != KDP_PACKET_RECEIVED)
	{
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		/* Didn't receive PacketId. */
		goto RetryReceivePacket;
	}

	/*
			if (Packet.PacketId != ExpectedPacketId)
			{
				// Ask for a resend!
				continue;
			}
	*/

	/* Step 5 - Read Checksum */
	KdStatus = KdpReceiveBuffer(&PendingPacket->Packet.Checksum, sizeof(ULONG));
	if (KdStatus != KDP_PACKET_RECEIVED)
	{
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		/* Didn't receive Checksum. */
		goto RetryReceivePacket;
	}


	/* Step 6 - Handle control packets */
	if (PendingPacket->Packet.PacketLeader == CONTROL_PACKET_LEADER)
	{
		switch (PendingPacket->Packet.PacketType)
		{
		case PACKET_TYPE_KD_ACKNOWLEDGE:
			/* Are we waiting for an ACK packet? */
			if (ExpectPacketType == PACKET_TYPE_KD_ACKNOWLEDGE &&
				PendingPacket->Packet.PacketId == (CurrentPacketId & ~SYNC_PACKET_ID))
			{
				if (DangleAcknowledgePacket)
				{
					/* Remote acknowledges the last packet */
					//注意这个也不需要
					CurrentPacketId ^= 1;
				}
				return PendingPacket;
			}
			else
			{
				break;
				//return KDP_PACKET_RESEND;
			}
			/* That's not what we were waiting for, start over */
			break;

		case PACKET_TYPE_KD_RESET:
			if (ForcePorteOutput)
			{
				KdpDprintf(L"KdReceivePacket - got PACKET_TYPE_KD_RESET\n");
			}
			/*CurrentPacketId = INITIAL_PACKET_ID;
			RemotePacketId = INITIAL_PACKET_ID;
			KdpSendControlPacket(PACKET_TYPE_KD_RESET, 0);*/
			/*KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID);
			KdpSymbolReportSynthetic();*/



			CurrentPacketId = INITIAL_PACKET_ID;
			RemotePacketId = INITIAL_PACKET_ID;
			KdpSendControlPacket(PACKET_TYPE_KD_RESET, 0);
			goto RetryReceivePacket;
			//	break;
				//return KDP_PACKET_RECEIVED;
				/* Fall through */

		case PACKET_TYPE_KD_RESEND:
			if (ForcePorteOutput)
			{
				KdpDprintf(L"KdReceivePacket - got PACKET_TYPE_KD_RESEND\n");
			}
			KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
			goto RetryReceivePacket;
			//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID);
			/* Remote wants us to resend the last packet */
			//return KDP_PACKET_RESEND;

		default:
		{
			if (ForcePorteOutput)
			{
				KdpDprintf(L"KdReceivePacket - got unknown control packet,PacketType %08x ByteCount %08x PacketId %08x Checksum %08x\n", PendingPacket->Packet.PacketType, PendingPacket->Packet.ByteCount, PendingPacket->Packet.PacketId, PendingPacket->Packet.Checksum);
			}
			/* We got an invalid packet, ignore it and start over */
			//return KDP_PACKET_RESEND;
			//continue;
			break;
		}
		}
	}
	else if (PendingPacket->Packet.PacketLeader != PACKET_LEADER)
	{
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		goto RetryReceivePacket;
	}

	if (PendingPacket->Packet.PacketType == PACKET_TYPE_KD_ACKNOWLEDGE && PendingPacket->Packet.PacketLeader == CONTROL_PACKET_LEADER)
	{
		/* We received something different */
		//KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		/**/
		if (DangleAcknowledgePacket)
		{
			if (PendingPacket->Packet.PacketId == (CurrentPacketId & ~SYNC_PACKET_ID))
			{
				//!确认这个是不是要处理
				CurrentPacketId ^= 1;
			}
		}
		//CurrentPacketId ^= 1;
		return PendingPacket;
	}


	/* Get size of the message header */
	PendingPacket->MessageHeader.MaximumLength = sizeof(DBGKD_MANIPULATE_STATE64);
	PendingPacket->MessageHeader.Length = PendingPacket->MessageHeader.MaximumLength;
	/* Packet smaller than expected or too big? */
	if (PendingPacket->Packet.ByteCount < PendingPacket->MessageHeader.Length ||
		PendingPacket->Packet.ByteCount > PACKET_MAX_SIZE)
	{
		if (TRUE)
		{
			Print(L"KdReceivePacket - too few data (%08x) for type %08x %08x %08x \n",
				PendingPacket->Packet.ByteCount, PendingPacket->MessageHeader.Length, ExpectPacketType, PendingPacket->Packet.PacketType);
		}
		//PendingPacket->MessageHeader.Length = PendingPacket->Packet.ByteCount;

		/*KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
		*/
		//return KDP_PACKET_RESEND;
		//这个可能是一个PACKET_TYPE_KD_ACKNOWLEDGE
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		goto RetryReceivePacket;
	}
	if (PendingPacket->MessageHeader.Length == 0)
	{
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		goto RetryReceivePacket;
	}
	//KdpDprintf(L"KdReceivePacket - got normal PacketType, Buffer = %p\n", MessageHeader->Buffer);
	if (PendingPacket->MessageHeader.Buffer == NULL)
	{
		PendingPacket->MessageHeader.Buffer = AllocateZeroPool(PendingPacket->MessageHeader.MaximumLength);
	}
	else
	{
		KdpZeroMemory(PendingPacket->MessageHeader.Buffer, PendingPacket->MessageHeader.MaximumLength);

	}

	if (PendingPacket->MessageHeader.Buffer == NULL)
	{

		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		goto RetryReceivePacket;
	}
	if (PendingPacket->MessageHeader.Length == 0)
	{
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		goto RetryReceivePacket;
	}
	/* Receive the message header data */
	KdStatus = KdpReceiveBuffer(PendingPacket->MessageHeader.Buffer,
		PendingPacket->MessageHeader.Length);
	if (KdStatus != KDP_PACKET_RECEIVED)
	{
		if (ForcePorteOutput)
		{
			/* Didn't receive data. Packet needs to be resent. */
			KdpDprintf(L"KdReceivePacket - Didn't receive message header data.\n");
		}
		
		/*KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);*/
		//return KDP_PACKET_RESEND;
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		goto RetryReceivePacket;
	}
	PDBGKD_MANIPULATE_STATE64 pManipulateState = (PDBGKD_MANIPULATE_STATE64)(PendingPacket->MessageHeader.Buffer);
	if (!(pManipulateState->ApiNumber >= DbgKdApiMin && pManipulateState->ApiNumber <= DbgKdApiMax))
	{
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		goto RetryReceivePacket;
	}
	else if (pManipulateState->ApiNumber == DbgKdContinueApi2 || pManipulateState->ApiNumber == DbgKdContinueApi)
	{

		termconfirmed = TRUE;
	}
	//KdpDprintf(L"KdReceivePacket - got normal PacketType 3\n");
	UCHAR termByte = 0;
	/* Calculate checksum for the header data */
	ULONG Checksum = KdpCalculateChecksum(PendingPacket->MessageHeader.Buffer,
		PendingPacket->MessageHeader.Length);
	/* Calculate the length of the message data */

	PendingPacket->MessageData.MaximumLength = KDP_MSG_BUFFER_SIZE;
	if (PendingPacket->MessageData.Buffer == NULL)
	{
		PendingPacket->MessageData.Buffer = AllocateZeroPool(PendingPacket->MessageData.MaximumLength);
	}
	else
	{
		KdpZeroMemory(PendingPacket->MessageData.Buffer, PendingPacket->MessageData.MaximumLength);

	}
	if (PendingPacket->MessageData.Buffer == NULL)
	{
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		goto RetryReceivePacket;
	}
	ULONG DataLength = PendingPacket->Packet.ByteCount - PendingPacket->MessageHeader.Length;
	/* Shall we receive message data? */
	if (DataLength == 0)
	{

		KdStatus = KdpReceiveBuffer(&termByte, sizeof(UCHAR));
		/*if (termconfirmed)
		{
			KdpDprintf(L"termconfirmed\r\n");
		}*/

		if (!IntegralityCheckgManipulatePacketPromise(PendingPacket))
		{
			//晚自习检查还是要的
			KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
			goto RetryReceivePacket;
		}

		KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, PendingPacket->Packet.PacketId);
		PendingPacket->MessageData.Length = 0;
		return PendingPacket;


	}
	else if (DataLength >= PACKET_MAX_SIZE)
	{
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		goto RetryReceivePacket;
	}

	/* Set the length of the message data */

	PendingPacket->MessageData.Length = (USHORT)DataLength;

	/* Do we have data? */
	if (PendingPacket->MessageData.Length)
	{
		//KdpDprintf(L"KdReceivePacket - got data\n");

		/* Receive the message data */
		KdStatus = KdpReceiveBuffer(PendingPacket->MessageData.Buffer,
			PendingPacket->MessageData.Length);
		if (KdStatus != KDP_PACKET_RECEIVED)
		{
			if (ForcePorteOutput)
			{
				/* Didn't receive data. Start over. */
				KdpDprintf(L"KdReceivePacket - Didn't receive message data.\n");
			}
			
			/*KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
			KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);*/
			//return KDP_PACKET_RESEND;
			KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
			goto RetryReceivePacket;
		}

		/* Add cheksum for message data */
		Checksum += KdpCalculateChecksum(PendingPacket->MessageData.Buffer,
			PendingPacket->MessageData.Length);
	}


	/* We must receive a PACKET_TRAILING_BYTE now */
	KdStatus = KdpReceiveBuffer(&termByte, sizeof(UCHAR));

	if (!IntegralityCheckgManipulatePacketPromise(PendingPacket))
	{
		//晚自习检查还是要的
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		goto RetryReceivePacket;
	}
	//为什么这个Checksum校验失败
	if (pManipulateState->ApiNumber == DbgKdSetContextApi || pManipulateState->ApiNumber == DbgKdWriteControlSpaceApi)
	{
		if (KdStatus != KDP_PACKET_RECEIVED || termByte != PACKET_TRAILING_BYTE)
		{
			//这个是不是要留着
			KdpReceiveByteToTerminableByte();
			//注意
			//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, CurrentPacketId);
			KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, PendingPacket->Packet.PacketId);
			return PendingPacket;
			/*KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
			goto RetryReceivePacket;*/
		}
		else {
			//注意
			//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, CurrentPacketId);
			KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, PendingPacket->Packet.PacketId);
			return PendingPacket;
		}
	}

	if (KdStatus != KDP_PACKET_RECEIVED || termByte != PACKET_TRAILING_BYTE)
	{
		if (ForcePorteOutput)
		{
			KdpDprintf(L"KdReceivePacket - wrong trailing byte (0x%x), status 0x%x\n", termByte, KdStatus);
		}
		
		/*KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);*/
		//return KDP_PACKET_RESEND;
		//这个是不是还要允许
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		goto RetryReceivePacket;
	}
	else if (termconfirmed)
	{
		if (pManipulateState->ApiNumber == DbgKdContinueApi2 || pManipulateState->ApiNumber == DbgKdContinueApi)
		{
			//注意
			//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, CurrentPacketId);
			KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, PendingPacket->Packet.PacketId);
			return PendingPacket;

		}
		else
		{
			KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
			goto RetryReceivePacket;
		}

	}


	//注意
	//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, CurrentPacketId);

	/* Acknowledge the received packet */
	KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, PendingPacket->Packet.PacketId);

	/*/* Check if the received PacketId is ok #1#
	 *
	 */
	if (PendingPacket->Packet.PacketId != RemotePacketId)
	{
		/* Continue with next packet*/
		//continue;
		//这个是不是还要允许,还是按照原作者
		return PendingPacket;
	}
	else
	{
		RemotePacketId ^= 1;
	}

	/* Did we get the right packet type? */
	if (ExpectPacketType == PendingPacket->Packet.PacketType)
	{
		/* Yes, return success */
		//KdpDprintf(L"KdReceivePacket - all ok\n");

		return PendingPacket;
	}

	/* Compare checksum */
	if (PendingPacket->Packet.Checksum != Checksum)
	{
		if (ForcePorteOutput)
		{
			KdpDprintf(L"KdReceivePacket - wrong cheksum, got %x, calculated %x\n",
				PendingPacket->Packet.Checksum, Checksum);
		}
		
		/*KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);*/
		//return KDP_PACKET_RECEIVED;
		//return KDP_PACKET_RESEND;
		//continue;
		//这个是不是还要允许,还是按照原作者
		return PendingPacket;
	}
	return PendingPacket;
	/*if (ForcePorteOutput)
	{
		/* We received something different, ignore it. #1#
		KdpDprintf(L"KdReceivePacket - wrong PacketType\n");
	}
	continue;*/
}

KDP_STATUS
NTAPI
KdpReceiveByteToTerminableAsync()
{

	KDP_STATUS ret = KDP_PACKET_RECEIVED;
	UCHAR termbyte = 0;
	while (ret != KDP_PACKET_TIMEOUT)
	{
		ret = KdpReceiveBufferAsync(&termbyte, 1);

		if (termbyte == PACKET_TRAILING_BYTE)
		{
			ret = KDP_PACKET_RECEIVED;
			return ret;
			break;
		}
		else
		{
			continue;
		}
	}

	return ret;

}

KDP_STATUS
NTAPI
KdpReceivePacketLeaderAsync(
	OUT PULONG PacketLeader)
{
	UCHAR Index = 0, Byte, Buffer[4];
	int KdStatus;

	/* Set first character to 0 */
	Buffer[0] = 0;

	do
	{
		/* Receive a single byte */
		KdStatus = KdpReceiveByteAsync(&Byte);

		/* Check for timeout */
		if (KdStatus == KDP_PACKET_TIMEOUT)
		{
			/* Check if we already got a breakin byte */
			if (Buffer[0] == BREAKIN_PACKET_BYTE)
			{
				KdpDprintf(L"KdpReceiveByte Async Break Instruction Exception KDP_PACKET_RESEND\n");
				//__debugbreak();
				return KDP_PACKET_RESEND;
			}

			/* Report timeout */
			return KDP_PACKET_TIMEOUT;
		}

		/* Check if we received a byte */
		if (KdStatus == KDP_PACKET_RECEIVED)
		{
			/* Check if this is a valid packet leader byte */
			if (Byte == PACKET_LEADER_BYTE ||
				Byte == CONTROL_PACKET_LEADER_BYTE)
			{
				/* Check if we match the first byte */
				if (Byte != Buffer[0])
				{
					/* No, this is the new byte 0! */
					Index = 0;
				}

				/* Store the byte in the buffer */
				Buffer[Index] = Byte;

				/* Continue with next byte */
				Index++;
				continue;
			}

			/* Check for breakin byte */
			if (Byte == BREAKIN_PACKET_BYTE)
			{
				KdpDprintf(L"KdpReceiveByte Async Break Instruction Exception\n");
				//__debugbreak();
				Index = 0;
				Buffer[0] = Byte;
				return KDP_PACKET_RESEND;
				continue;
			}
		}

		/* Restart */
		Index = 0;
		Buffer[0] = 0;
	} while (Index < 4);

	/* Enable the debugger */
	/*KD_DEBUGGER_NOT_PRESENT = FALSE;
	SharedUserData->KdDebuggerEnabled |= 0x00000002;*/

	/* Return the received packet leader */
	*PacketLeader = *(PULONG)Buffer;

	return KDP_PACKET_RECEIVED;
}


KDP_STATUS
NTAPI
KdpReceivePacketLeader(
	OUT PULONG PacketLeader)
{
	UCHAR Index = 0, Byte, Buffer[4];
	int KdStatus;

	/* Set first character to 0 */
	Buffer[0] = 0;

	do
	{
		/* Receive a single byte */
		KdStatus = KdpReceiveByte(&Byte);

		/* Check for timeout */
		if (KdStatus == KDP_PACKET_TIMEOUT)
		{
			/* Check if we already got a breakin byte */
			if (Buffer[0] == BREAKIN_PACKET_BYTE)
			{
				KdpDprintf(L"KdpReceiveByte Async Break Instruction Exception KDP_PACKET_RESEND\n");
				//__debugbreak();
				return KDP_PACKET_RESEND;
			}

			/* Report timeout */
			return KDP_PACKET_TIMEOUT;
		}

		/* Check if we received a byte */
		if (KdStatus == KDP_PACKET_RECEIVED)
		{
			/* Check if this is a valid packet leader byte */
			if (Byte == PACKET_LEADER_BYTE ||
				Byte == CONTROL_PACKET_LEADER_BYTE)
			{
				/* Check if we match the first byte */
				if (Byte != Buffer[0])
				{
					/* No, this is the new byte 0! */
					Index = 0;
				}

				/* Store the byte in the buffer */
				Buffer[Index] = Byte;

				/* Continue with next byte */
				Index++;
				continue;
			}

			/* Check for breakin byte */
			if (Byte == BREAKIN_PACKET_BYTE)
			{
				KdpDprintf(L"KdpReceiveByte Async Break Instruction Exception\n");
				//__debugbreak();
				Index = 0;
				Buffer[0] = Byte;
				//return KDP_PACKET_RECEIVED;
				continue;
			}
		}

		/* Restart */
		Index = 0;
		Buffer[0] = 0;
	} while (Index < 4);

	/* Enable the debugger */
	/*KD_DEBUGGER_NOT_PRESENT = FALSE;
	SharedUserData->KdDebuggerEnabled |= 0x00000002;*/

	/* Return the received packet leader */
	*PacketLeader = *(PULONG)Buffer;

	return KDP_PACKET_RECEIVED;
}



BOOLEAN
NTAPI
KdpPollBreakInWithPortLock(VOID)
{
	BOOLEAN DoBreak = FALSE;

	/* First make sure that KD is enabled */
	if (KdDebuggerEnabled)
	{
		/* Check if a CTRL-C is in the queue */
		if (KdpContext.KdpControlCPending)
		{
			/* Set it and prepare for break */
			DoBreak = TRUE;
			//KdpContext.KdpControlCPending = FALSE;
		}
		else
		{
			/* Now get a packet */
			if (KdReceivePacket(PACKET_TYPE_KD_POLL_BREAKIN,
				NULL,
				NULL,
				NULL,
				&KdpContext) == KdPacketReceived)
			{
				/* Successful breakin */
				DoBreak = TRUE;
			}
		}
	}
	if (DoBreak)
	{
		__debugbreak();
	}
	/* Tell the caller to do a break */
	return DoBreak;
}

ULONG
NTAPI
KdpAddBreakpoint(IN PVOID Address)
{
	KD_BREAKPOINT_TYPE Content;
	ULONG i;
	NTSTATUS Status;

	/* Check whether we are not setting a breakpoint twice */
	for (i = 0; i < KD_BREAKPOINT_MAX; i++)
	{
		/* Check if the breakpoint is valid */
		if ((KdpBreakpointTable[i].Flags & KD_BREAKPOINT_ACTIVE) &&
			(KdpBreakpointTable[i].Address == Address))
		{
			/* Were we not able to remove it earlier? */
			if (KdpBreakpointTable[i].Flags & KD_BREAKPOINT_EXPIRED)
			{
				/* Just re-use it! */
				KdpBreakpointTable[i].Flags &= ~KD_BREAKPOINT_EXPIRED;
				return i + 1;
			}
			else
			{
				/* Fail */
				return 0;
			}
		}
	}

	/* Find a free entry */
	for (i = 0; i < KD_BREAKPOINT_MAX; i++)
	{
		if (KdpBreakpointTable[i].Flags == 0)
			break;
	}

	/* Fail if no free entry was found */
	if (i == KD_BREAKPOINT_MAX) return 0;

	/* Save the breakpoint */
	KdpBreakpointTable[i].Address = Address;

	/* If we are setting the breakpoint in user space, save the active process context */
	/*if (Address < KD_HIGHEST_USER_BREAKPOINT_ADDRESS)
		KdpBreakpointTable[i].DirectoryTableBase = KeGetCurrentThread()->ApcState.Process->DirectoryTableBase[0];
		*/

		/* Try to save the old instruction */
	Status = KdpCopyMemoryChunks((ULONG_PTR)Address,
		&Content,
		KD_BREAKPOINT_SIZE,
		0,
		MMDBG_COPY_UNSAFE,
		NULL);
	if (NT_SUCCESS(Status))
	{
		/* Memory accessible, set the breakpoint */
		KdpBreakpointTable[i].Content = Content;
		KdpBreakpointTable[i].Flags = KD_BREAKPOINT_ACTIVE;

		/* Write the breakpoint */
		Status = KdpCopyMemoryChunks((ULONG_PTR)Address,
			&KdpBreakpointInstruction,
			KD_BREAKPOINT_SIZE,
			0,
			MMDBG_COPY_UNSAFE | MMDBG_COPY_WRITE,
			NULL);
		if (!NT_SUCCESS(Status))
		{
			/* This should never happen */
			KdpDprintf(L"Unable to write breakpoint to address 0x%p\n", Address);
			return 0;
		}
		UINT8 KdpBreakpointInstructionChk = *((UINT8*)Address);
		if (KdpBreakpointInstructionChk != (UINT8)KdpBreakpointInstruction)
		{
			KdpDprintf(L"Unable to write breakpoint to address 0x%p,unmatch KdpBreakpointInstruction\n", Address);
			return 0;
		}



	}
	else
	{
		/* Memory is inaccessible now, setting breakpoint is deferred */
		KdpDprintf(L"Failed to set breakpoint at address 0x%p, adding deferred breakpoint.\n", Address);
		KdpBreakpointTable[i].Flags = KD_BREAKPOINT_ACTIVE | KD_BREAKPOINT_PENDING;
		KdpOweBreakpoint = TRUE;
		return 0;
	}

	/* Return the breakpoint handle */
	return i + 1;
}

VOID
NTAPI
KdSetOwedBreakpoints(VOID)
{
	BOOLEAN Enable;
	KD_BREAKPOINT_TYPE Content;
	ULONG i;
	NTSTATUS Status;

	/* If we don't owe any breakpoints, just return */
	if (!KdpOweBreakpoint) return;

	/* Enter the debugger */
	Enable = KdEnterDebugger(NULL, NULL);

	/*
	 * Suppose we succeed in setting all the breakpoints.
	 * If we fail to do so, the flag will be set again.
	 */
	KdpOweBreakpoint = FALSE;

	/* Loop through current breakpoints and try to set or delete the pending ones */
	for (i = 0; i < KD_BREAKPOINT_MAX; i++)
	{
		if (KdpBreakpointTable[i].Flags & (KD_BREAKPOINT_PENDING | KD_BREAKPOINT_EXPIRED))
		{
			/*
			 * Set the breakpoint only if it is in kernel space, or if it is
			 * in user space and the active process context matches.
			 */
			if (KdpBreakpointTable[i].Address < KD_HIGHEST_USER_BREAKPOINT_ADDRESS)
				//&&KdpBreakpointTable[i].DirectoryTableBase != KeGetCurrentThread()->ApcState.Process->DirectoryTableBase[0])
			{
				KdpOweBreakpoint = TRUE;
				continue;
			}

			/* Try to save the old instruction */
			Status = KdpCopyMemoryChunks((ULONG_PTR)KdpBreakpointTable[i].Address,
				&Content,
				KD_BREAKPOINT_SIZE,
				0,
				MMDBG_COPY_UNSAFE,
				NULL);
			if (!NT_SUCCESS(Status))
			{
				/* Memory is still inaccessible, breakpoint setting will be deferred again */
				// KdpDprintf(L"Failed to set deferred breakpoint at address 0x%p\n",
				//            KdpBreakpointTable[i].Address);
				KdpOweBreakpoint = TRUE;
				continue;
			}

			/* Check if we need to write the breakpoint */
			if (KdpBreakpointTable[i].Flags & KD_BREAKPOINT_PENDING)
			{
				/* Memory accessible, set the breakpoint */
				KdpBreakpointTable[i].Content = Content;

				/* Write the breakpoint */
				Status = KdpCopyMemoryChunks((ULONG_PTR)KdpBreakpointTable[i].Address,
					&KdpBreakpointInstruction,
					KD_BREAKPOINT_SIZE,
					0,
					MMDBG_COPY_UNSAFE | MMDBG_COPY_WRITE,
					NULL);
				if (!NT_SUCCESS(Status))
				{
					/* This should never happen */
					KdpDprintf(L"Unable to write deferred breakpoint to address 0x%p\n",
						KdpBreakpointTable[i].Address);
					KdpOweBreakpoint = TRUE;
				}
				else
				{
					KdpBreakpointTable[i].Flags = KD_BREAKPOINT_ACTIVE;
				}

				continue;
			}

			/* Check if we need to restore the original instruction */
			if (KdpBreakpointTable[i].Flags & KD_BREAKPOINT_EXPIRED)
			{
				/* Write it back */
				Status = KdpCopyMemoryChunks((ULONG_PTR)KdpBreakpointTable[i].Address,
					&KdpBreakpointTable[i].Content,
					KD_BREAKPOINT_SIZE,
					0,
					MMDBG_COPY_UNSAFE | MMDBG_COPY_WRITE,
					NULL);
				if (!NT_SUCCESS(Status))
				{
					/* This should never happen */
					KdpDprintf(L"Unable to delete deferred breakpoint at address 0x%p\n",
						KdpBreakpointTable[i].Address);
					KdpOweBreakpoint = TRUE;
				}
				else
				{
					/* Check if the breakpoint is suspended */
					if (KdpBreakpointTable[i].Flags & KD_BREAKPOINT_SUSPENDED)
					{
						KdpBreakpointTable[i].Flags = KD_BREAKPOINT_SUSPENDED | KD_BREAKPOINT_ACTIVE;
					}
					else
					{
						/* Invalidate it */
						KdpBreakpointTable[i].Flags = 0;
					}
				}

				continue;
			}
		}
	}

	/* Exit the debugger */
	KdExitDebugger(Enable);
}

BOOLEAN
NTAPI
KdpLowWriteContent(IN ULONG BpIndex)
{
	NTSTATUS Status;

	/* Make sure that the breakpoint is actually active */
	if (KdpBreakpointTable[BpIndex].Flags & KD_BREAKPOINT_PENDING)
	{
		/* So we have a valid breakpoint, but it hasn't been used yet... */
		KdpBreakpointTable[BpIndex].Flags &= ~KD_BREAKPOINT_PENDING;
		return TRUE;
	}

	/* Is the original instruction a breakpoint anyway? */
	if (KdpBreakpointTable[BpIndex].Content == KdpBreakpointInstruction)
	{
		/* Then leave it that way... */
		return TRUE;
	}

	/* We have an active breakpoint with an instruction to bring back. Do it. */
	Status = KdpCopyMemoryChunks((ULONG_PTR)KdpBreakpointTable[BpIndex].Address,
		&KdpBreakpointTable[BpIndex].Content,
		KD_BREAKPOINT_SIZE,
		0,
		MMDBG_COPY_UNSAFE | MMDBG_COPY_WRITE,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		/* Memory is inaccessible now, restoring original instruction is deferred */
		// KdpDprintf(L"Failed to delete breakpoint at address 0x%p\n",
		//            KdpBreakpointTable[BpIndex].Address);
		KdpBreakpointTable[BpIndex].Flags |= KD_BREAKPOINT_EXPIRED;
		KdpOweBreakpoint = TRUE;
		return FALSE;
	}

	/* Everything went fine, return */
	return TRUE;
}

BOOLEAN
NTAPI
KdpLowRestoreBreakpoint(IN ULONG BpIndex)
{
	NTSTATUS Status;

	/* Were we not able to remove it earlier? */
	if (KdpBreakpointTable[BpIndex].Flags & KD_BREAKPOINT_EXPIRED)
	{
		/* Just re-use it! */
		KdpBreakpointTable[BpIndex].Flags &= ~KD_BREAKPOINT_EXPIRED;
		return TRUE;
	}

	/* Are we merely writing a breakpoint on top of another breakpoint? */
	if (KdpBreakpointTable[BpIndex].Content == KdpBreakpointInstruction)
	{
		/* Nothing to do */
		return TRUE;
	}

	/* Ok, we actually have to overwrite the instruction now */
	Status = KdpCopyMemoryChunks((ULONG_PTR)KdpBreakpointTable[BpIndex].Address,
		&KdpBreakpointInstruction,
		KD_BREAKPOINT_SIZE,
		0,
		MMDBG_COPY_UNSAFE | MMDBG_COPY_WRITE,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		/* Memory is inaccessible now, restoring breakpoint is deferred */
		// KdpDprintf(L"Failed to restore breakpoint at address 0x%p\n",
		//            KdpBreakpointTable[BpIndex].Address);
		KdpBreakpointTable[BpIndex].Flags |= KD_BREAKPOINT_PENDING;
		KdpOweBreakpoint = TRUE;
		return FALSE;
	}

	/* Clear any possible previous pending flag and return success */
	KdpBreakpointTable[BpIndex].Flags &= ~KD_BREAKPOINT_PENDING;
	return TRUE;
}

BOOLEAN
NTAPI
KdpDeleteBreakpoint(IN ULONG BpEntry)
{
	ULONG BpIndex = BpEntry - 1;

	/* Check for invalid breakpoint entry */
	if (!BpEntry || (BpEntry > KD_BREAKPOINT_MAX)) return FALSE;

	/* If the specified breakpoint table entry is not valid, then return FALSE. */
	if (!KdpBreakpointTable[BpIndex].Flags) return FALSE;

	/* Check if the breakpoint is suspended */
	if (KdpBreakpointTable[BpIndex].Flags & KD_BREAKPOINT_SUSPENDED)
	{
		/* Check if breakpoint is not being deleted */
		if (!(KdpBreakpointTable[BpIndex].Flags & KD_BREAKPOINT_EXPIRED))
		{
			/* Invalidate it and return success */
			KdpBreakpointTable[BpIndex].Flags = 0;
			return TRUE;
		}
	}

	/* Restore original data, then invalidate it and return success */
	if (KdpLowWriteContent(BpIndex)) KdpBreakpointTable[BpIndex].Flags = 0;
	return TRUE;
}

BOOLEAN
NTAPI
KdpDeleteBreakpointRange(IN PVOID Base,
	IN PVOID Limit)
{
	ULONG BpIndex;
	BOOLEAN DeletedBreakpoints;

	/* Assume no breakpoints will be deleted */
	DeletedBreakpoints = FALSE;

	/* Loop the breakpoint table */
	for (BpIndex = 0; BpIndex < KD_BREAKPOINT_MAX; BpIndex++)
	{
		/* Make sure that the breakpoint is active and matches the range. */
		if ((KdpBreakpointTable[BpIndex].Flags & KD_BREAKPOINT_ACTIVE) &&
			((KdpBreakpointTable[BpIndex].Address >= Base) &&
				(KdpBreakpointTable[BpIndex].Address <= Limit)))
		{
			/* Delete it, and remember if we succeeded at least once */
			if (KdpDeleteBreakpoint(BpIndex + 1)) DeletedBreakpoints = TRUE;
		}
	}

	/* Return whether we deleted anything */
	return DeletedBreakpoints;
}

VOID
NTAPI
KdpRestoreAllBreakpoints(VOID)
{
	ULONG BpIndex;

	/* No more suspended Breakpoints */
	BreakpointsSuspended = FALSE;

	/* Loop the breakpoints */
	for (BpIndex = 0; BpIndex < KD_BREAKPOINT_MAX; BpIndex++)
	{
		/* Check if they are valid, suspended breakpoints */
		if ((KdpBreakpointTable[BpIndex].Flags & KD_BREAKPOINT_ACTIVE) &&
			(KdpBreakpointTable[BpIndex].Flags & KD_BREAKPOINT_SUSPENDED))
		{
			/* Unsuspend them */
			KdpBreakpointTable[BpIndex].Flags &= ~KD_BREAKPOINT_SUSPENDED;
			KdpLowRestoreBreakpoint(BpIndex);
		}
	}
}

VOID
NTAPI
KdpSuspendBreakPoint(IN ULONG BpEntry)
{
	ULONG BpIndex = BpEntry - 1;

	/* Check if this is a valid, unsuspended breakpoint */
	if ((KdpBreakpointTable[BpIndex].Flags & KD_BREAKPOINT_ACTIVE) &&
		!(KdpBreakpointTable[BpIndex].Flags & KD_BREAKPOINT_SUSPENDED))
	{
		/* Suspend it */
		KdpBreakpointTable[BpIndex].Flags |= KD_BREAKPOINT_SUSPENDED;
		KdpLowWriteContent(BpIndex);
	}
}

VOID
NTAPI
KdpSuspendAllBreakPoints(VOID)
{
	ULONG BpEntry;

	/* Breakpoints are suspended */
	BreakpointsSuspended = TRUE;

	/* Loop every breakpoint */
	for (BpEntry = 1; BpEntry <= KD_BREAKPOINT_MAX; BpEntry++)
	{
		/* Suspend it */
		KdpSuspendBreakPoint(BpEntry);
	}
}


VOID
NTAPI
KdpGetStateChange(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PCONTEXT Context, DEBUG_CPU_CONTEXT* CpuContext)
{

	//ULONG i;

	/* Check for success */
	if (NT_SUCCESS(State->u.Continue2.ContinueStatus))
	{
		/* Check if we're tracing */
		if (State->u.Continue2.u.ControlSet.TraceFlag)
		{
			/* Enable TF */
			Context->EFlags |= EFLAGS_TF;
			if (CpuContext)
			{

				CommandStepping(CpuContext);
			}
		}
		else
		{
			/* Remove it */
			Context->EFlags &= ~EFLAGS_TF;
			if (CpuContext)
			{

				CommandSteppingCleanup(CpuContext);
			}
		}

		/*/* Loop all processors #1#
		for (i = 0; i < KeNumberProcessors; i++)
		{
			/* Get the PRCB and update DR7 and DR6 #1#
			Prcb = KiProcessorBlock[i];
			Prcb->ProcessorState.SpecialRegisters.KernelDr7 =
				State->u.Continue2.ControlSet.Dr7;
			Prcb->ProcessorState.SpecialRegisters.KernelDr6 = 0;
		}*/

		/* Check if we have new symbol information */
		if (State->u.Continue2.u.ControlSet.CurrentSymbolStart != 1)
		{
			/* Update it */
			KdpCurrentSymbolStart =
				State->u.Continue2.u.ControlSet.CurrentSymbolStart;
			KdpCurrentSymbolEnd = State->u.Continue2.u.ControlSet.CurrentSymbolEnd;
		}
	}
	return;
}
/* PRIVATE FUNCTIONS **********************************************************/

/******************************************************************************
 * \name KdpCalculateChecksum
 * \brief Calculates the checksum for the packet data.
 * \param Buffer Pointer to the packet data.
 * \param Length Length of data in bytes.
 * \return The calculated checksum.
 * \sa http://www.vista-xp.co.uk/forums/technical-reference-library/2540-basics-debugging.html
 */

VOID
NTAPI
KdpSendControlPacket(
	IN USHORT PacketType,
	IN ULONG PacketId OPTIONAL)
{
	KD_PACKET Packet;

	Packet.PacketLeader = CONTROL_PACKET_LEADER;
	Packet.PacketId = PacketId;
	Packet.ByteCount = 0;
	Packet.Checksum = 0;
	Packet.PacketType = PacketType;

	/*if(PacketType== PACKET_TYPE_KD_RESEND)
	{
		DumpRet(0x38);
		Print(L"PACKET_TYPE_KD_RESEND\r\n");
	}*/
	if (gVmbusWindbgProtocol == NativeCom)
	{
		KdpSendBuffer(&Packet, sizeof(KD_PACKET));
	}
	else
	{
		KdSendPacketVmbus(&Packet, NULL, NULL, NULL);
	}
	return;
}

VOID
NTAPI
KdReceivePacketRetryResend()
{
	KdpReceiveByteToTerminable();
	//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
	KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
	return;
}


VOID CopyMessageString(OUT PSTRING MessageOut, IN PSTRING MessageIn)
{
	MessageOut->Buffer = MessageIn->Buffer;
	MessageOut->Length = MessageIn->Length;
	MessageOut->MaximumLength = MessageIn->MaximumLength;
	return;
}

BOOLEAN
NTAPI
KdpReadVirtualMemoryHook(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context);
VOID
NTAPI
ClearPacket(PKD_PACKETEXTRA Packet)
{
	if (Packet->MessageHeader.Buffer)
	{
		FreePool(Packet->MessageHeader.Buffer);
		Packet->MessageHeader.Buffer = NULL;
	}
	if (Packet->MessageData.Buffer)
	{
		FreePool(Packet->MessageData.Buffer);
		Packet->MessageData.Buffer = NULL;
	}

	FreePool(Packet);
	return;
}
PKD_PACKETEXTRA
NTAPI
FilterPengdingManipulatePacket(IN ULONG ExpectPacketType)
{
	PKD_PACKETEXTRA PendingPacket = NULL;

	PKD_PACKETEXTRA TermPacket = NULL;
	if (!IsListEmptyUefi(&pPengdingManipulatePacket->List))
	{
		for (PLIST_ENTRY_UEFI nextentry = pPengdingManipulatePacket->List.Flink; nextentry != (PLIST_ENTRY_UEFI)pPengdingManipulatePacket; nextentry = nextentry->Flink)
		{
			PKD_PACKETEXTRA tmpPacket = (PKD_PACKETEXTRA)nextentry;
			if (tmpPacket->MessageHeader.Buffer != NULL)
			{
				PDBGKD_MANIPULATE_STATE64 pManipulateState = (PDBGKD_MANIPULATE_STATE64)(tmpPacket->MessageHeader.Buffer);
				if (tmpPacket->Packet.PacketType == ExpectPacketType) {
					if (pManipulateState->ApiNumber == DbgKdContinueApi2 || pManipulateState->ApiNumber == DbgKdContinueApi)
					{
						if (TermPacket == NULL)
						{
							TermPacket = tmpPacket;
						}
						else
						{
							PLIST_ENTRY_UEFI tmpentry = nextentry->Flink;

							RemoveEntryListUefi(&tmpPacket->List);

							ClearPacket(tmpPacket);


							nextentry->Flink = tmpentry;
							continue;
						}
					}
					else if (pManipulateState->ApiNumber != 0)
					{
						if (PendingPacket == NULL)
						{
							PendingPacket = tmpPacket;
							break;
						}
					}
				}
			}
			else if (tmpPacket->Packet.PacketType == ExpectPacketType)
			{
				if (PendingPacket == NULL)
				{
					PendingPacket = tmpPacket;
					break;
				}
			}
		}


		if (PendingPacket != NULL)
		{

			RemoveEntryListUefi(&PendingPacket->List);

			return PendingPacket;
		}
		else if (TermPacket != NULL)
		{
			PendingPacket = TermPacket;
			RemoveEntryListUefi(&PendingPacket->List);

			return PendingPacket;
		}
	}

	return PendingPacket;
}



KDP_STATUS
NTAPI
KdReceivePacket(
	IN ULONG PacketType,
	OUT PSTRING MessageHeader,
	OUT PSTRING MessageData,
	OUT PULONG DataLength,
	IN OUT PKD_CONTEXT KdContext)
{
	BOOLEAN ForceConsoleOutputStack = FALSE;
	BOOLEAN  DangleAcknowledgePacket = TRUE;
	if (DataLength)
	{
		*DataLength = 0;
	}
	if(!KdContext)
	{
		KdContext = &KdpContext;
	}
	
	//int failedcount = 0;
	/*if (PacketType == PACKET_TYPE_KD_POLL_BREAKIN)
	{
		return KdPollBreakIn();
	}*/
	while (TRUE)
	{
		PKD_PACKETEXTRA PendingPacket = FilterPengdingManipulatePacket(PacketType);


		/*if (termconfirmed)
		{
			if (PendingPacket != NULL)
			{
				KdpDprintf(L"flt %08x  %08x \r\n", PendingPacket->Packet.PacketType, PacketType);
			}
			else
			{
				KdpDprintf(L"flt %08x  %08x \r\n", 0, PacketType);
			}
		}*/
		if (PendingPacket != NULL)
		{
			if (PendingPacket->Packet.PacketType == PacketType)
			{
				if (KdContext->KdpControlCPending == TRUE)
				{
					InsertTailListUefi(&pPengdingManipulatePacket->List, &PendingPacket->List);
					return KDP_PACKET_RECEIVED;

				}

				if (DangleAcknowledgePacket && PacketType == PACKET_TYPE_KD_ACKNOWLEDGE)
				{
					if (PendingPacket->Packet.PacketId == (CurrentPacketId & ~SYNC_PACKET_ID))
					{
						/* Remote acknowledges the last packet */
						CurrentPacketId ^= 1;

					}
				}

				if (MessageHeader)
				{
					CopyMessageString(MessageHeader, &PendingPacket->MessageHeader);

				}
				if (MessageData)
				{
					CopyMessageString(MessageData, &PendingPacket->MessageData);
					if (DataLength)
					{
						*DataLength = MessageData->Length;
					}
				}
				FreePool(PendingPacket);

				return KDP_PACKET_RECEIVED;
			}
			else
			{
				InsertTailListUefi(&pPengdingManipulatePacket->List, &PendingPacket->List);
				Print(L"InsertTailListUefi PacketType match failed\r\n");
			}
		}
		else if (!IsListEmptyUefi(&pPengdingManipulatePacket->List) && PacketType == PACKET_TYPE_KD_ACKNOWLEDGE)
		{
			return KDP_PACKET_RECEIVED;
		}
	RetryReceivePacket:
		PendingPacket = EatPendingManipulatePacketPromise(PacketType);
		if (PendingPacket == NULL)
		{
			/*if (failedcount > 2)
			{
				KdpDprintf(L"EatPendingManipulatePacketPromise get wrong failedcount %x\n",
					failedcount);
				return KDP_PACKET_RESEND;
			}
			failedcount++;
			continue;*/
			return KDP_PACKET_RESEND;
		}
		else
		{

			if (!IntegralityCheckgManipulatePacketPromise(PendingPacket))
			{
				KdpDprintf(L"IntegralityCheckgManipulatePacketPromise failed %08x  %08x \r\n", PendingPacket->Packet.PacketType, PacketType);
				//continue;
				ClearPacket(PendingPacket);
				return KDP_PACKET_RESEND;
			}

			/*if (termconfirmed)
			{
				KdpDprintf(L"tm %08x  %08x \r\n", PendingPacket->Packet.PacketType, PacketType);
			}*/

		}
		/*else
		{
			PDBGKD_MANIPULATE_STATE64 State = (PDBGKD_MANIPULATE_STATE64)PendingPacket->MessageHeader.Buffer;
			if (PendingPacket->Packet.PacketLeader == PACKET_LEADER && State->ApiNumber == DbgKdReadVirtualMemoryApi)
			{

				STRING Data;
				CopyMessageString(&Data, &PendingPacket->MessageData);
				if (KdpReadVirtualMemoryHook(State, &Data, NULL)) {
					PendingPacket = NULL;
					continue;
				}


			}
		}*/


		if (PendingPacket->Packet.PacketType == PacketType)
		{
			//KdpDprintf(L"match PacketType ok\r\n");
			if (KdContext->KdpControlCPending == TRUE)
			{
				InsertTailListUefi(&pPengdingManipulatePacket->List, &PendingPacket->List);
				return KDP_PACKET_RECEIVED;
			}

			if(DangleAcknowledgePacket&& PacketType == PACKET_TYPE_KD_ACKNOWLEDGE)
			{
				if (PendingPacket->Packet.PacketId == (CurrentPacketId & ~SYNC_PACKET_ID))
				{
					/* Remote acknowledges the last packet */
					CurrentPacketId ^= 1;
					
				}
			}

			if (MessageHeader)
			{
				CopyMessageString(MessageHeader, &PendingPacket->MessageHeader);

			}
			if (MessageData)
			{
				CopyMessageString(MessageData, &PendingPacket->MessageData);
				if (DataLength)
				{
					*DataLength = MessageData->Length;
				}
			}
			FreePool(PendingPacket);
			return KDP_PACKET_RECEIVED;

		}
		else if (PendingPacket->Packet.PacketLeader != CONTROL_PACKET_LEADER && PacketType == PACKET_TYPE_KD_ACKNOWLEDGE)
		{

			/*if (pPengdingManipulatePacket)
			{
				if (pPengdingManipulatePacket->MessageHeader.Buffer)
				{
					FreePool(pPengdingManipulatePacket->MessageHeader.Buffer);
					pPengdingManipulatePacket->MessageHeader.Buffer = NULL;
				}
				if (pPengdingManipulatePacket->MessageData.Buffer)
				{
					FreePool(pPengdingManipulatePacket->MessageData.Buffer);
					pPengdingManipulatePacket->MessageData.Buffer = NULL;
				}
				FreePool(pPengdingManipulatePacket);
			}*/

			InsertTailListUefi(&pPengdingManipulatePacket->List, &PendingPacket->List);
			if (ForceConsoleOutputStack)
			{
				UINT32  packetlen_aligned = (UINT32)ALIGN_UP_FIX(sizeof(KD_PACKET), 0x10);
				dumpbuf((void*)&PendingPacket->Packet, packetlen_aligned);
				int len = ListSizeUefi(&pPengdingManipulatePacket->List);

				KdpDprintf(L"ack %08x %p %p %p \r\n", (UINT32)((PacketType << 16) + len), pPengdingManipulatePacket, pPengdingManipulatePacket->List.Flink, pPengdingManipulatePacket->List.Blink);
				KdpDprintf(L"ack %08x %p %p %p \r\n", PendingPacket->Packet.PacketType, PendingPacket, PendingPacket->List.Flink, PendingPacket->List.Blink);
				//goto RetryReceivePacket;
			}

			return KDP_PACKET_RECEIVED;
		}
		else if (PendingPacket->Packet.PacketLeader == CONTROL_PACKET_LEADER && PendingPacket->Packet.PacketType == PACKET_TYPE_KD_ACKNOWLEDGE && PacketType != PACKET_TYPE_KD_ACKNOWLEDGE)
		{

			/*if (pPengdingManipulatePacket)
			{
				if (pPengdingManipulatePacket->MessageHeader.Buffer)
				{
					FreePool(pPengdingManipulatePacket->MessageHeader.Buffer);
					pPengdingManipulatePacket->MessageHeader.Buffer = NULL;
				}
				if (pPengdingManipulatePacket->MessageData.Buffer)
				{
					FreePool(pPengdingManipulatePacket->MessageData.Buffer);
					pPengdingManipulatePacket->MessageData.Buffer = NULL;
				}
				FreePool(pPengdingManipulatePacket);
			}*/

			InsertTailListUefi(&pPengdingManipulatePacket->List, &PendingPacket->List);
			if (ForceConsoleOutputStack)
			{
				UINT32  packetlen_aligned = (UINT32)ALIGN_UP_FIX(sizeof(KD_PACKET), 0x10);
				dumpbuf((void*)&PendingPacket->Packet, packetlen_aligned);

				int len = ListSizeUefi(&pPengdingManipulatePacket->List);

				KdpDprintf(L"ctl %08x %p %p %p \r\n", (UINT32)((PacketType << 16) + len), pPengdingManipulatePacket, pPengdingManipulatePacket->List.Flink, pPengdingManipulatePacket->List.Blink);
				KdpDprintf(L"ctl %08x %p %p %p \r\n", PendingPacket->Packet.PacketType, PendingPacket, PendingPacket->List.Flink, PendingPacket->List.Blink);
			}
			goto RetryReceivePacket;
			//return KDP_PACKET_RECEIVED;
			//return KDP_PACKET_RESEND;
		}
		else
		{
			UINT32  packetlen_aligned = (UINT32)ALIGN_UP_FIX(sizeof(KD_PACKET), 0x10);
			dumpbuf((void*)&PendingPacket->Packet, packetlen_aligned);
			//goto RetryReceivePacket;
			//continue;
			Print(L"error packet %08x %08x \r\n", PendingPacket->Packet.PacketLeader, PendingPacket->Packet.PacketType);
			//这个还是要重试
			ClearPacket(PendingPacket);
			return KDP_PACKET_RESEND;
		}

	}
	return KDP_PACKET_RECEIVED;
}

KDP_STATUS
NTAPI
KdReceivePacket1(
	IN ULONG PacketType,
	OUT PSTRING MessageHeader,
	OUT PSTRING MessageData,
	OUT PULONG DataLength,
	IN OUT PKD_CONTEXT KdContext)
{
	UCHAR Byte = 0;
	int KdStatus;
	KD_PACKET Packet;
	ULONG Checksum;

	/* Special handling for breakin packet */
	if (PacketType == PACKET_TYPE_KD_POLL_BREAKIN)
	{
		return KdPollBreakIn();
	}
	while (TRUE)
	{
		if (MessageHeader)
		{
			MessageHeader->MaximumLength = sizeof(DBGKD_MANIPULATE_STATE64);
		}
		/* Step 1 - Read PacketLeader */
		KdStatus = KdpReceivePacketLeader(&Packet.PacketLeader);
		if (KdStatus != KDP_PACKET_RECEIVED)
		{
			/* Check if we got a breakin  */
			if (KdStatus == KDP_PACKET_RESEND)
			{
				//KdContext->KdpControlCPending = TRUE;
			}
			return KdStatus;
		}

		/* Step 2 - Read PacketType */
		KdStatus = KdpReceiveBuffer(&Packet.PacketType, sizeof(USHORT));
		if (KdStatus != KDP_PACKET_RECEIVED)
		{
			/* Didn't receive a PacketType. */
			return KdStatus;
		}

		/* Check if we got a resend packet */
		if (Packet.PacketLeader == CONTROL_PACKET_LEADER &&
			Packet.PacketType == PACKET_TYPE_KD_RESEND)
		{
			return KDP_PACKET_RESEND;
		}

		/* Step 3 - Read ByteCount */
		KdStatus = KdpReceiveBuffer(&Packet.ByteCount, sizeof(USHORT));
		if (KdStatus != KDP_PACKET_RECEIVED)
		{
			/* Didn't receive ByteCount. */
			return KdStatus;
		}

		/* Step 4 - Read PacketId */
		KdStatus = KdpReceiveBuffer(&Packet.PacketId, sizeof(ULONG));
		if (KdStatus != KDP_PACKET_RECEIVED)
		{
			/* Didn't receive PacketId. */
			return KdStatus;
		}

		/*
				if (Packet.PacketId != ExpectedPacketId)
				{
					// Ask for a resend!
					continue;
				}
		*/

		/* Step 5 - Read Checksum */
		KdStatus = KdpReceiveBuffer(&Packet.Checksum, sizeof(ULONG));
		if (KdStatus != KDP_PACKET_RECEIVED)
		{
			/* Didn't receive Checksum. */
			return KdStatus;
		}

		/* Step 6 - Handle control packets */
		if (Packet.PacketLeader == CONTROL_PACKET_LEADER)
		{
			switch (Packet.PacketType)
			{
			case PACKET_TYPE_KD_ACKNOWLEDGE:
				/* Are we waiting for an ACK packet? */
				if (PacketType == PACKET_TYPE_KD_ACKNOWLEDGE &&
					Packet.PacketId == (CurrentPacketId & ~SYNC_PACKET_ID))
				{
					/* Remote acknowledges the last packet */
					CurrentPacketId ^= 1;
					return KDP_PACKET_RECEIVED;
				}
				else
				{
					break;
					//return KDP_PACKET_RESEND;
				}
				/* That's not what we were waiting for, start over */
				break;

			case PACKET_TYPE_KD_RESET:
				if (ForcePorteOutput)
				{
					KdpDprintf(L"KdReceivePacket - got PACKET_TYPE_KD_RESET\n");
				}
				/*CurrentPacketId = INITIAL_PACKET_ID;
				RemotePacketId = INITIAL_PACKET_ID;
				KdpSendControlPacket(PACKET_TYPE_KD_RESET, 0);*/
				/*KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID);
				KdpSymbolReportSynthetic();*/



				CurrentPacketId = INITIAL_PACKET_ID;
				RemotePacketId = INITIAL_PACKET_ID;
				KdpSendControlPacket(PACKET_TYPE_KD_RESET, 0);

				//	break;
					//return KDP_PACKET_RECEIVED;
					/* Fall through */

			case PACKET_TYPE_KD_RESEND:
				if (ForcePorteOutput)
				{
					KdpDprintf(L"KdReceivePacket - got PACKET_TYPE_KD_RESEND\n");
				}
				//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID);
				/* Remote wants us to resend the last packet */
				return KDP_PACKET_RESEND;

			default:
			{
				if (ForcePorteOutput)
				{
					KdpDprintf(L"KdReceivePacket - got unknown control packet,PacketType %08x ByteCount %08x PacketId %08x Checksum %08x\n", Packet.PacketType, Packet.ByteCount, Packet.PacketId, Packet.Checksum);
				}
				/* We got an invalid packet, ignore it and start over */
				//return KDP_PACKET_RESEND;
				continue;
				//break;
			}
			}
		}
		else if (Packet.PacketLeader != PACKET_LEADER)
		{
			KdReceivePacketRetryResend();
			continue;
		}

		/* Did we wait for an ack packet? */
		if (PacketType == PACKET_TYPE_KD_ACKNOWLEDGE)
		{
			/* We received something different */
			//KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
			CurrentPacketId ^= 1;
			return KDP_PACKET_RECEIVED;
		}


		if (!MessageHeader)
		{
			return KDP_PACKET_RECEIVED;
		}
		/* Get size of the message header */
		MessageHeader->Length = MessageHeader->MaximumLength;

		/* Packet smaller than expected or too big? */
		if (Packet.ByteCount < MessageHeader->Length ||
			Packet.ByteCount > PACKET_MAX_SIZE)
		{
			if (TRUE)
			{
				KdpDprintf(L"KdReceivePacket - too few data (%d) for type %d\n",
					Packet.ByteCount, MessageHeader->Length);
			}
			MessageHeader->Length = Packet.ByteCount;
			KdReceivePacketRetryResend();
			/*KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
			KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);*/
			//return KDP_PACKET_RESEND;
			continue;
		}

		//KdpDprintf(L"KdReceivePacket - got normal PacketType, Buffer = %p\n", MessageHeader->Buffer);

		/* Receive the message header data */
		KdStatus = KdpReceiveBuffer(MessageHeader->Buffer,
			MessageHeader->Length);
		if (KdStatus != KDP_PACKET_RECEIVED)
		{
			if (TRUE)
			{
				/* Didn't receive data. Packet needs to be resent. */
				KdpDprintf(L"KdReceivePacket - Didn't receive message header data.\n");
			}
			KdReceivePacketRetryResend();
			/*KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
			KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);*/
			//return KDP_PACKET_RESEND;
			continue;
		}

		//KdpDprintf(L"KdReceivePacket - got normal PacketType 3\n");

		/* Calculate checksum for the header data */
		Checksum = KdpCalculateChecksum(MessageHeader->Buffer,
			MessageHeader->Length);

		/* Calculate the length of the message data */
		*DataLength = Packet.ByteCount - MessageHeader->Length;

		/* Shall we receive message data? */
		if (MessageData)
		{
			/* Set the length of the message data */
			MessageData->Length = (USHORT)*DataLength;

			/* Do we have data? */
			if (MessageData->Length)
			{
				//KdpDprintf(L"KdReceivePacket - got data\n");

				/* Receive the message data */
				KdStatus = KdpReceiveBuffer(MessageData->Buffer,
					MessageData->Length);
				if (KdStatus != KDP_PACKET_RECEIVED)
				{
					if (TRUE)
					{
						/* Didn't receive data. Start over. */
						KdpDprintf(L"KdReceivePacket - Didn't receive message data.\n");
					}
					KdReceivePacketRetryResend();
					/*KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
					KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);*/
					//return KDP_PACKET_RESEND;
					continue;
				}

				/* Add cheksum for message data */
				Checksum += KdpCalculateChecksum(MessageData->Buffer,
					MessageData->Length);
			}
		}

		/* We must receive a PACKET_TRAILING_BYTE now */
		KdStatus = KdpReceiveBuffer(&Byte, sizeof(UCHAR));

		PDBGKD_MANIPULATE_STATE64 pManipulateState = (PDBGKD_MANIPULATE_STATE64)(MessageHeader->Buffer);
		//为什么这个Checksum校验失败
		if (pManipulateState->ApiNumber == DbgKdSetContextApi || pManipulateState->ApiNumber == DbgKdWriteControlSpaceApi)
		{
			KdpReceiveByteToTerminable();
			KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, Packet.PacketId);
			return KDP_PACKET_RECEIVED;
		}

		if (KdStatus != KDP_PACKET_RECEIVED || Byte != PACKET_TRAILING_BYTE)
		{
			if (TRUE)
			{
				KdpDprintf(L"KdReceivePacket - wrong trailing byte (0x%x), status 0x%x\n", Byte, KdStatus);
			}
			KdReceivePacketRetryResend();
			/*KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
			KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);*/
			//return KDP_PACKET_RESEND;
			continue;
		}






		/* Acknowledge the received packet */
		KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, Packet.PacketId);

		/*/* Check if the received PacketId is ok #1#
		 *
		 */
		if (Packet.PacketId != RemotePacketId)
		{
			/* Continue with next packet*/
			continue;
		}

		/* Did we get the right packet type? */
		if (PacketType == Packet.PacketType)
		{
			/* Yes, return success */
			//KdpDprintf(L"KdReceivePacket - all ok\n");
			RemotePacketId ^= 1;
			return KDP_PACKET_RECEIVED;
		}

		/* Compare checksum */
		if (Packet.Checksum != Checksum)
		{
			if (TRUE)
			{
				KdpDprintf(L"KdReceivePacket - wrong cheksum, got %x, calculated %x\n",
					Packet.Checksum, Checksum);
			}
			KdReceivePacketRetryResend();
			/*KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
			KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);*/
			return KDP_PACKET_RECEIVED;
			//return KDP_PACKET_RESEND;
			//continue;
		}
		return KDP_PACKET_RECEIVED;
		/*if (ForcePorteOutput)
		{
			/* We received something different, ignore it. #1#
			KdpDprintf(L"KdReceivePacket - wrong PacketType\n");
		}
		continue;*/
	}
	return KDP_PACKET_RECEIVED;
	//return KDP_PACKET_RESEND;

}



VOID
NTAPI
KdSendPacketWithoutAcknowledge(
	IN ULONG PacketType,
	IN PSTRING MessageHeader,
	IN PSTRING MessageData,
	IN OUT PKD_CONTEXT KdContext)
{
	if (gVmbusWindbgProtocol == NativeCom)
	{
		KD_PACKET Packet;
		//int KdStatus;
		ULONG Retries;

		/* Initialize a KD_PACKET */
		Packet.PacketLeader = PACKET_LEADER;
		Packet.PacketType = (USHORT)PacketType;
		Packet.ByteCount = MessageHeader->Length;
		Packet.Checksum = KdpCalculateChecksum(MessageHeader->Buffer,
			MessageHeader->Length);

		/* If we have message data, add it to the packet */
		if (MessageData && MessageData->Length > 0)
		{
			Packet.ByteCount += MessageData->Length;
			Packet.Checksum += KdpCalculateChecksum(MessageData->Buffer,
				MessageData->Length);
		}

		Retries = KdContext->KdpDefaultRetries;


		/* Set the packet id */
		Packet.PacketId = CurrentPacketId;
		//Packet.PacketId = 0;

		/* Send the packet header to the KD port */
		KdpSendBuffer(&Packet, sizeof(KD_PACKET));

		/* Send the message header */
		KdpSendBuffer(MessageHeader->Buffer, MessageHeader->Length);

		/* If we have message data, also send it */
		if (MessageData)
		{
			if (MessageData->Length > 0)
			{
				KdpSendBuffer(MessageData->Buffer, MessageData->Length);
			}
		}

		/* Finalize with a trailing byte */
		KdpSendByte(PACKET_TRAILING_BYTE);
	}

	return;
}

KDP_STATUS
NTAPI
KdSendPacket(
	IN ULONG PacketType,
	IN PSTRING MessageHeader,
	IN PSTRING MessageData,
	IN OUT PKD_CONTEXT KdContext)
{
	KD_PACKET Packet;
	KDP_STATUS KdStatus;
	ULONG Retries;
	if (!KdContext)
	{
		KdContext = &KdpContext;
	}
	BOOLEAN KdpControlReturnSave = KdContext->KdpControlReturn;
	KdContext->KdpControlReturn = FALSE;
	/* Initialize a KD_PACKET */
	Packet.PacketLeader = PACKET_LEADER;
	Packet.PacketType = (USHORT)PacketType;
	Packet.ByteCount = MessageHeader->Length;
	Packet.Checksum = KdpCalculateChecksum(MessageHeader->Buffer,
		MessageHeader->Length);

	/* If we have message data, add it to the packet */
	if (MessageData != NULL)
	{
		if (MessageData->Length > 0)
		{
			Packet.ByteCount += MessageData->Length;
			Packet.Checksum += KdpCalculateChecksum(MessageData->Buffer,
				MessageData->Length);
		}
		else
		{
			//KdpDprintf(L"data len chk\rn");
			//__debugbreak();
		}
	}

	Retries = KdContext->KdpDefaultRetries;

	while (TRUE)
	{
		/* Set the packet id */
		Packet.PacketId = CurrentPacketId;
		if (gVmbusWindbgProtocol == NativeCom)
		{

			/* Send the packet header to the KD port */
			KdpSendBuffer(&Packet, sizeof(KD_PACKET));

			/* Send the message header */
			KdpSendBuffer(MessageHeader->Buffer, MessageHeader->Length);

			/* If we have message data, also send it */
			if (MessageData != NULL)
			{
				if (MessageData->Length > 0)
				{
					KdpSendBuffer(MessageData->Buffer, MessageData->Length);
				}
				else
				{
					//KdpDprintf(L"data len chk2\rn");
					//__debugbreak();
				}
			}

			/* Finalize with a trailing byte */
			KdpSendByte(PACKET_TRAILING_BYTE);
		}
		else {
			KdSendPacketVmbus(&Packet, MessageHeader, MessageData, KdContext);
		}
		KdContext->KdpControlCPending = FALSE;
		/* Wait for acknowledge */
		KdStatus = KdReceivePacket(PACKET_TYPE_KD_ACKNOWLEDGE,
			NULL,
			NULL,
			NULL,
			KdContext);

		/* Did we succeed? */
		if (KdStatus == KDP_PACKET_RECEIVED)
		{
			/* Packet received, we can quit the loop */
			//!!注意,这个是不是要处理			
			CurrentPacketId &= ~SYNC_PACKET_ID;
			Retries = KdContext->KdpDefaultRetries;
			/*return KDP_PACKET_RECEIVED;
			break;*/
		}
		else if (KdStatus == KDP_PACKET_RESEND)
		{
			//KdpDprintf(L"fake KDP_PACKET_RESEND\r\n");
			continue;
		}
		else if (KdStatus == KDP_PACKET_TIMEOUT)
		{
			/*KdpDprintf(L"fake KDP_PACKET_TIMEOUT\r\n");
			continue;*/

			/* Timeout, decrement the retry count */
			if (Retries > 0)
				Retries--;

			/*
			 * If the retry count reaches zero, bail out
			 * for packet types allowed to timeout.
			 */
			if (Retries == 0)
			{
				ULONG MessageId = *(PULONG)MessageHeader->Buffer;
				switch (PacketType)
				{
				case PACKET_TYPE_KD_DEBUG_IO:
				{
					if (MessageId != DbgKdPrintStringApi) continue;
					break;
				}

				case PACKET_TYPE_KD_STATE_CHANGE32:
				case PACKET_TYPE_KD_STATE_CHANGE64:
				{
					if (MessageId != DbgKdLoadSymbolsStateChange) continue;
					break;
				}

				case PACKET_TYPE_KD_FILE_IO:
				{
					if (MessageId != DbgKdCreateFileApi) continue;
					break;
				}
				}

				/* Reset debugger state */
			   // KD_DEBUGGER_NOT_PRESENT = TRUE;
			   // SharedUserData->KdDebuggerEnabled &= ~0x00000002;
				CurrentPacketId = INITIAL_PACKET_ID | SYNC_PACKET_ID;
				RemotePacketId = INITIAL_PACKET_ID;


			}
			return KdStatus;
		}
		else if (KdStatus != KDP_PACKET_RECEIVED)
		{
			//KdpDprintf(L"data len chk3\rn");
			//__debugbreak();
			return KdStatus;
		}
		else
		{
			//KdpDprintf(L"fake KDP_PACKET_RESEND2 %08x\r\n", KdStatus);
			continue;
		}
		if (KdpControlReturnSave == TRUE)
		{
			KdContext->KdpControlCPending = FALSE;
			return KdStatus;
		}

		KdContext->KdpControlCPending = TRUE;
		KdStatus = KdReceivePacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			NULL,
			NULL,
			NULL,
			KdContext);

		/* Did we succeed? */
		if (KdStatus == KDP_PACKET_RECEIVED)
		{
			/* Packet received, we can quit the loop */
			//!!注意,这个是不是要处理
			//CurrentPacketId &= ~SYNC_PACKET_ID;
			Retries = KdContext->KdpDefaultRetries;
			return KDP_PACKET_RECEIVED;
			break;
		}
		else if (KdStatus == KDP_PACKET_RESEND)
		{
			//KdpDprintf(L"fake KDP_PACKET_RESEND\r\n");
			return KDP_PACKET_RECEIVED;
			//continue;
		}
		else
		{
			//KdpDprintf(L"fake KDP_PACKET_RESEND3 %08x\r\n", KdStatus);
			continue;
		}
		// else (KdStatus == KDP_PACKET_RESEND) /* Resend the packet */

		/* Packet timed out, send it again */
		/*if (ForceConsoleOutput)
		{
			KdpDprintf(L"KdSendPacket got KdStatus 0x%x\n", KdStatus);
		}*/
	}
	return KdStatus;
}

/*
 * @implemented
 */
BOOLEAN
NTAPI
KdPollBreakIn(VOID)
{
	BOOLEAN DoBreak = FALSE;

	/* Now get a packet */
	if (KdReceivePacket(PACKET_TYPE_KD_POLL_BREAKIN,
		NULL,
		NULL,
		NULL,
		&KdpContext) == KDP_PACKET_RECEIVED)
	{
		/* Successful breakin */
		DoBreak = TRUE;

	}



	/* Tell the caller to do a break */
	return DoBreak;
}

VOID NTAPI PspDumpThreads(BOOLEAN SystemThreads);


/*
VOID
NTAPI
KdpMoveMemory(
	_In_ PVOID Destination,
	_In_ PVOID Source,
	_In_ SIZE_T Length)
{
	PCHAR DestinationBytes, SourceBytes;

	/* Copy the buffers 1 byte at a time #1#
	DestinationBytes = Destination;
	SourceBytes = Source;
	while (Length--) *DestinationBytes++ = *SourceBytes++;
	return;
}*/
VOID
NTAPI
KdpMoveMemory(
	_In_ PVOID Destination,
	_In_ PVOID Source,
	_In_ UINT32 Length)
{

	hvcopymemory(Destination, Source, Length);
	return;
}
/*VOID
NTAPI
KdpMoveMemory(
	_In_ PVOID Destination,
	_In_ PVOID Source,
	_In_ UINT32 Length)
{



	UINT64* Pointer64;
	UINT64* Pointer264;
	UINT8* Pointer;
	UINT8* Pointer2;
	Pointer64 = (UINT64*)Destination;
	Pointer264 = (UINT64*)Source;
	if (Length >= 8)
	{
		while (Length >= 8) {
			*(Pointer64++) = MmioRead64((UINT64)(Pointer264++));
			Length -= 8;
		}
	}
	if (Length > 0) {
		Pointer = (UINT8*)Pointer64;
		Pointer2 = (UINT8*)Pointer264;
		while (Length-- != 0) {
			*(Pointer++) = MmioRead8((UINT64)(Pointer2++));
		}
	}

	return;
}*/

/*VOID
NTAPI
KdpZeroMemory(
	_In_ PVOID Destination,
	_In_ SIZE_T Length)
{
	PCHAR DestinationBytes;

	/* Zero the buffer 1 byte at a time #1#
	DestinationBytes = Destination;
	while (Length--) *DestinationBytes++ = 0;
	return;
}*/
/*
VOID
NTAPI
KdpZeroMemory(
	_In_ PVOID Destination,
	_In_ UINT32 Length)
{
	UINT64* Pointer64 = (UINT64*)Destination;
	if (Length >= 8)
	{
		while (Length >= 8) {
			MmioWrite64((UINT64)(Pointer64++), 0);
			Length -= 8;
		}
	}
	if (Length > 0) {
		UINT8* Pointer = (UINT8*)Pointer64;
		while (Length-- != 0) {
			MmioWrite8((UINT64)(Pointer++), 0);
		}
	}
	return;


}*/

VOID
NTAPI
KdpZeroMemory(
	_In_ PVOID Destination,
	_In_ UINT32 Length)
{
	hvresetmemory(Destination, Length);
	return;

}
/* PRIVATE FUNCTIONS *********************************************************/
NTSTATUS
NTAPI
MmDbgCopyMemory(IN ULONG64 Address,
	IN PVOID Buffer,
	IN ULONG Size,
	IN ULONG Flags)
{

	PVOID CopyDestination, CopySource;
	/* Check what kind of operation this is */
	if (Flags & MMDBG_COPY_WRITE)
	{
		/* Write */
		CopyDestination = (PVOID)Address;
		CopySource = (PVOID)Buffer;
	}
	else
	{
		/* Read */
		CopyDestination = (PVOID)Buffer;
		CopySource = (PVOID)Address;
	}

	KdpMoveMemory(CopyDestination, CopySource, Size);
	return STATUS_SUCCESS;

}
NTSTATUS
NTAPI
KdpCopyMemoryChunks(
	_In_ ULONG64 Address,
	_In_ PVOID Buffer,
	_In_ ULONG TotalSize,
	_In_ ULONG ChunkSize,
	_In_ ULONG Flags,
	_Out_opt_ PULONG ActualSize)
{
	NTSTATUS Status;
	ULONG RemainingLength, CopyChunk;

	/* Check if we didn't get a chunk size or if it is too big */
	if (ChunkSize == 0)
	{
		/* Default to 4 byte chunks */
		ChunkSize = 4;
	}
	else if (ChunkSize > MMDBG_COPY_MAX_SIZE)
	{
		/* Normalize to maximum size */
		ChunkSize = MMDBG_COPY_MAX_SIZE;
	}

	/* Copy the whole range in aligned chunks */
	RemainingLength = TotalSize;
	CopyChunk = 1;
	while (RemainingLength > 0)
	{
		/*
		 * Determine the best chunk size for this round.
		 * The ideal size is aligned, isn't larger than the
		 * the remaining length and respects the chunk limit.
		 */
		while (((CopyChunk * 2) <= RemainingLength) &&
			(CopyChunk < ChunkSize) &&
			((Address & ((CopyChunk * 2) - 1)) == 0))
		{
			/* Increase it */
			CopyChunk *= 2;
		}

		/*
		 * The chunk size can be larger than the remaining size if this
		 * isn't the first round, so check if we need to shrink it back.
		 */
		while (CopyChunk > RemainingLength)
		{
			/* Shrink it */
			CopyChunk /= 2;
		}

		/* Do the copy */
		Status = MmDbgCopyMemory(Address, Buffer, CopyChunk, Flags);
		if (!NT_SUCCESS(Status))
		{
			/* Copy failed, break out */
			break;
		}

		/* Update pointers and length for the next run */
		Address = Address + CopyChunk;
		Buffer = (PVOID)((ULONG_PTR)Buffer + CopyChunk);
		RemainingLength = RemainingLength - CopyChunk;
	}

	/* We may have modified executable code, flush the instruction cache */
	KeSweepICache((PVOID)(ULONG_PTR)Address, TotalSize);

	/*
	 * Return the size we managed to copy and return
	 * success if we could copy the whole range.
	 */
	if (ActualSize) *ActualSize = TotalSize - RemainingLength;
	return RemainingLength == 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}



BOOLEAN  KdpReadVirtualMemoryMap(PSTRING Data, UINT64 TargetBaseAddress, ULONG Length, PCONTEXT Context)
{
	if(TargetBaseAddress==0)
	{
		return FALSE;
	}
	if (Context!=NULL)
	{
		if (LowCheckMemoryAddr(Context->Rsp))
		{
			//
			if (TargetBaseAddress >= Context->Rsp - 0x1000 && TargetBaseAddress < Context->Rsp + 0x1000)
			{
				KdpMoveMemory((void*)Data->Buffer, (void*)(TargetBaseAddress), Length);


				return TRUE;
			}
		}
	}
	for (int i = 0; i < KD_SYMBOLS_MAX; i++)
	{
		if (gsymmap[i].BaseOfAddr == 0)
		{
			return FALSE;
		}
		if (TargetBaseAddress >= gsymmap[i].BaseOfAddr && TargetBaseAddress + Length <= gsymmap[i].BaseOfAddr + gsymmap[i].SizeOfAddr)
		{
			UINT64 deltasize = TargetBaseAddress - gsymmap[i].BaseOfAddr;

			KdpMoveMemory((void*)Data->Buffer, (void*)(gsymmap[i].MapOfAddr + deltasize), Length);
			if (ForceConsoleOutput)
			{
				KdpDprintf(L"KdpReadVirtualMemory mSyntheticSymbolInfo TargetBaseAddress %p BaseOfDll %p MapOfDll %p Raw %p Length %08x ok\r\n", TargetBaseAddress, gsymmap[i].BaseOfAddr, gsymmap[i].MapOfAddr, (gsymmap[i].BaseOfAddr + deltasize), Length);
			}

			return TRUE;
		}


	}

	return FALSE;
}

VOID
NTAPI
KdpQueryMemory(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PCONTEXT Context)
{
	PDBGKD_QUERY_MEMORY Memory = &State->u.QueryMemory;
	STRING Header;
	NTSTATUS Status = STATUS_SUCCESS;

	/*
	/* Validate the address space #1#
	if (Memory->AddressSpace == DBGKD_QUERY_MEMORY_VIRTUAL)
	{
		/* Check if this is process memory #1#
		if ((PVOID)(ULONG_PTR)Memory->Address < MmHighestUserAddress)
		{
			/* It is #1#
			Memory->AddressSpace = DBGKD_QUERY_MEMORY_PROCESS;
		}
		else
		{
			/* Check if it's session space #1#
			if (MmIsSessionAddress((PVOID)(ULONG_PTR)Memory->Address))
			{
				/* It is #1#
				Memory->AddressSpace = DBGKD_QUERY_MEMORY_SESSION;
			}
			else
			{
				/* Not session space but some other kernel memory #1#
				Memory->AddressSpace = DBGKD_QUERY_MEMORY_KERNEL;
			}
		}

		/* Set flags #1#
		Memory->Flags = DBGKD_QUERY_MEMORY_READ |
			DBGKD_QUERY_MEMORY_WRITE |
			DBGKD_QUERY_MEMORY_EXECUTE;
	}
	else
	{
		/* Invalid #1#
		Status = STATUS_INVALID_PARAMETER;
	}*/
	Memory->AddressSpace = DBGKD_QUERY_MEMORY_KERNEL;

	Memory->Flags = DBGKD_QUERY_MEMORY_READ |
		DBGKD_QUERY_MEMORY_WRITE |
		DBGKD_QUERY_MEMORY_EXECUTE;

	/* Return structure */
	State->ReturnStatus = Status;
	Memory->Reserved = 0;

	/* Build header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;

	/* Send the packet */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
}

VOID
NTAPI
KdpSearchMemory(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	//PDBGKD_SEARCH_MEMORY SearchMemory = &State->u.SearchMemory;
	STRING Header;

	/* TODO */
	KdpDprintf(L"Memory Search support is unimplemented!\n");

	/* Send a failure packet */
	State->ReturnStatus = STATUS_UNSUCCESSFUL;
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
}

VOID
NTAPI
KdpFillMemory(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	//PDBGKD_FILL_MEMORY FillMemory = &State->u.FillMemory;
	STRING Header;

	/* TODO */
	KdpDprintf(L"Memory Fill support is unimplemented!\n");

	/* Send a failure packet */
	State->ReturnStatus = STATUS_UNSUCCESSFUL;
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
}

NTSTATUS
NTAPI
KdpSysWriteControlSpace(IN ULONG Processor,
	IN ULONG64 BaseAddress,
	IN PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ActualLength)
{
	//PVOID ControlStart;


	switch (BaseAddress)
	{
	case AMD64_DEBUG_CONTROL_SPACE_KSPECIAL:
		/* Copy SpecialRegisters */
		//ControlStart = &Prcb->ProcessorState.SpecialRegisters;
		*ActualLength = sizeof(KSPECIAL_REGISTERS);
		break;

	default:
		*ActualLength = 0;
		ASSERT(FALSE);
		return STATUS_UNSUCCESSFUL;
	}

	/* Copy the memory */
	//RtlCopyMemory(ControlStart, Buffer, min(Length, *ActualLength));

	return STATUS_SUCCESS;
}
NTSTATUS
NTAPI
KdpSysReadControlSpace(IN ULONG Processor,
	IN ULONG64 BaseAddress,
	IN PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ActualLength, DEBUG_CPU_CONTEXT* CpuContext)
{
	UINT64 CurrentThreadPtr = KeGetCurrentThread();
	KSPECIAL_REGISTERS WindbgSpecialRegistersCtx = { 0 };
	ULONG LengthSave = Length;
	PVOID ControlStart;
	switch (BaseAddress)
	{
	case AMD64_DEBUG_CONTROL_SPACE_KPCR:
		/* Copy a pointer to the Pcr */
		//ControlStart = &Pcr;
		*ActualLength = sizeof(PVOID);
		ControlStart = &gPcr;
		//KdpZeroMemory(Buffer, LengthSave);
		break;

	case AMD64_DEBUG_CONTROL_SPACE_KPRCB:
		/* Copy a pointer to the Prcb */
		//ControlStart = &Prcb;
		*ActualLength = sizeof(PVOID);
		ControlStart = &gPrcb;
		//KdpZeroMemory(Buffer, LengthSave);
		break;

	case AMD64_DEBUG_CONTROL_SPACE_KSPECIAL:
		/* Copy SpecialRegisters */
		if (CpuContext)
		{
			UefiCtx2WindbgSpecialRegistersCtx(CpuContext, &WindbgSpecialRegistersCtx);
		}

		ControlStart = &WindbgSpecialRegistersCtx;
		*ActualLength = sizeof(KSPECIAL_REGISTERS);
		break;

	case AMD64_DEBUG_CONTROL_SPACE_KTHREAD:
		/* Copy a pointer to the current Thread */
		//ControlStart = &Prcb->CurrentThread;

		*ActualLength = sizeof(PVOID);
		ControlStart = &CurrentThreadPtr;
		//KdpZeroMemory(Buffer, LengthSave);
		break;

	default:
		*ActualLength = 0;
		ASSERT(FALSE);
		KdpZeroMemory(Buffer, LengthSave);
		return STATUS_UNSUCCESSFUL;
	}

	/* Copy the memory */
	KdpMoveMemory(Buffer, ControlStart, min(Length, *ActualLength));

	/* Finish up */
	return STATUS_SUCCESS;
}
VOID
NTAPI
KdpWriteBreakpoint(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	PDBGKD_WRITE_BREAKPOINT64 Breakpoint = &State->u.WriteBreakPoint;
	STRING Header;

	/* Build header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	ASSERT(Data->Length == 0);
	if (ForceConsoleOutput)
	{
		KdpDprintf(L"KdpWriteBreakpoint %p\r\n", Breakpoint->BreakPointAddress);
	}

	/* Create the breakpoint */
	Breakpoint->BreakPointHandle =
		KdpAddBreakpoint((PVOID)(ULONG_PTR)Breakpoint->BreakPointAddress);
	if (!Breakpoint->BreakPointHandle)
	{
		/* We failed */
		State->ReturnStatus = STATUS_UNSUCCESSFUL;
	}
	else
	{
		/* Success! */
		State->ReturnStatus = STATUS_SUCCESS;
	}

	/* Send the packet */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
}

VOID
NTAPI
KdpRestoreBreakpoint(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	PDBGKD_RESTORE_BREAKPOINT RestoreBp = &State->u.RestoreBreakPoint;
	STRING Header;

	/* Fill out the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	ASSERT(Data->Length == 0);

	/* Get the version block */
	if (KdpDeleteBreakpoint(RestoreBp->BreakPointHandle))
	{
		/* We're all good */
		State->ReturnStatus = STATUS_SUCCESS;
	}
	else
	{
		State->ReturnStatus = STATUS_SUCCESS;
		/* We failed */
		//State->ReturnStatus = STATUS_UNSUCCESSFUL;
	}

	/* Send the packet */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
}

NTSTATUS
NTAPI
KdpWriteBreakPointEx(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	//PDBGKD_BREAKPOINTEX = &State->u.BreakPointEx;
	STRING Header;

	/* TODO */
	KdpDprintf(L"Extended Breakpoint Write support is unimplemented!\n");

	/* Send a failure packet */
	State->ReturnStatus = STATUS_UNSUCCESSFUL;
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		Data,
		&KdpContext);
	return STATUS_UNSUCCESSFUL;
}

VOID
NTAPI
KdpRestoreBreakPointEx(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	//PDBGKD_BREAKPOINTEX = &State->u.BreakPointEx;
	STRING Header;

	/* TODO */
	KdpDprintf(L"Extended Breakpoint Restore support is unimplemented!\n");

	/* Send a failure packet */
	State->ReturnStatus = STATUS_UNSUCCESSFUL;
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		Data,
		&KdpContext);
}

VOID
NTAPI
KdpWriteCustomBreakpoint(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	//PDBGKD_WRITE_CUSTOM_BREAKPOINT = &State->u.WriteCustomBreakpoint;
	STRING Header;

	/* Not supported */
	KdpDprintf(L"Custom Breakpoint Write is unimplemented\n");

	/* Send a failure packet */
	State->ReturnStatus = STATUS_UNSUCCESSFUL;
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
}

VOID
NTAPI
DumpTraceData(IN PSTRING TraceData)
{
	//  dumpbuf(TraceData->Buffer, TraceData->Length);
	return;
}

VOID
NTAPI
KdpSetCommonState(IN ULONG NewState,
	IN PCONTEXT Context,
	IN PDBGKD_ANY_WAIT_STATE_CHANGE WaitStateChange)
{
	ULONG InstructionCount;
	BOOLEAN HadBreakpoints;

	/* Setup common stuff available for all CPU architectures */
	WaitStateChange->NewState = NewState;
	WaitStateChange->ProcessorLevel = KdpNowKIRQL;
	WaitStateChange->Processor = (UINT16)GetProcessorIndex();
	WaitStateChange->NumberProcessors = (ULONG)mDebugCpuData.CpuCount;
	WaitStateChange->Thread = (ULONG64)(LONG_PTR)KeGetCurrentThread();
	WaitStateChange->ProgramCounter = (ULONG64)GetApicTimerCurrentCount();


	/* Zero out the entire Control Report*/
	KdpZeroMemory(&WaitStateChange->u1.AnyControlReport,
		sizeof(DBGKD_ANY_CONTROL_REPORT));

	/* Now copy the instruction stream and set the count */
	KdpCopyMemoryChunks((ULONG_PTR)WaitStateChange->ProgramCounter,
		&WaitStateChange->u1.ControlReport.InstructionStream[0],
		DBGKD_MAXSTREAM,
		0,
		MMDBG_COPY_UNSAFE,
		&InstructionCount);
	WaitStateChange->u1.ControlReport.InstructionCount = (USHORT)InstructionCount;

	/* Clear all the breakpoints in this region*/
	HadBreakpoints =
		KdpDeleteBreakpointRange((PVOID)(ULONG_PTR)WaitStateChange->ProgramCounter,
			(PVOID)((ULONG_PTR)WaitStateChange->ProgramCounter +
				WaitStateChange->u1.ControlReport.InstructionCount - 1));
	if (HadBreakpoints)
	{
		/* Copy the instruction stream again, this time without breakpoints*/
		KdpCopyMemoryChunks((ULONG_PTR)WaitStateChange->ProgramCounter,
			&WaitStateChange->u1.ControlReport.InstructionStream[0],
			InstructionCount,
			0,
			MMDBG_COPY_UNSAFE,
			NULL);
	}
	return;
}

VOID
NTAPI
KdpSysGetVersion(IN PDBGKD_GET_VERSION64 Version)
{
	/* Copy the version block */
	KdpMoveMemory(Version,
		&KdVersionBlock,
		sizeof(DBGKD_GET_VERSION64));
}

VOID
NTAPI
KdpGetVersion(IN PDBGKD_MANIPULATE_STATE64 State)
{
	STRING Header;

	/* Fill out the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;

	/* Get the version block */
	KdpSysGetVersion(&State->u.GetVersion64);
	//KdpDprintf(L"KdpGetVersion KernBase %p\r\n", State->u.GetVersion64.KernBase);
	/* Fill out the state */
	State->ApiNumber = DbgKdGetVersionApi;
	State->ReturnStatus = STATUS_SUCCESS;

	/* Send the packet */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
	return;
}BOOLEAN
NTAPI
FailedOperateMemoryAddressReport(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	PDBGKD_READ_MEMORY64 ReadMemory = &State->u.ReadMemory;
	ULONG Length = ReadMemory->TransferCount;
	UINT64 TargetBaseAddress = ReadMemory->TargetBaseAddress;
	STRING Header;
	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	if (!(!LowCheckMemoryAddr(ReadMemory->TargetBaseAddress) || Length == 0))
	{
		KdpDprintf(L"KdpReadVirtualMemory Failed Operate TargetBaseAddress %p\r\n", TargetBaseAddress);
		UefiMemoryDump(TargetBaseAddress, Length);
		HvMemoryDump(TargetBaseAddress);
	}



	KdpZeroMemory(Data->Buffer, Length);
	State->ReturnStatus = STATUS_SUCCESS;

	/* Return the actual length read */
	ReadMemory->ActualBytesRead = Length;
	Data->Length = (USHORT)Length;

	/* Send the packet */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		Data,
		&KdpContext);

	if (ForceConsoleOutput)
	{
		KdpDprintf(L"KdpReadVirtualMemory UefiMemoryPresent FALSE TargetBaseAddress %p\r\n", TargetBaseAddress);

	}
	//restart fail address check
	FailedOperateMemoryAddress1 = 0;
	FailedOperateMemoryAddress2 = 0;
	FailedOperateMemoryCount = 0;
	return TRUE;
}

BOOLEAN
NTAPI
FailedOperateMemoryAddressExsits(UINT64 TargetBaseAddress)
{
	for (int i = 0; i < KD_SYMBOLS_MAX; i++)
	{
		if (FailedOperateMemoryAddressArray[i] == TargetBaseAddress)
		{
			return TRUE;
		}

		if (FailedOperateMemoryAddressArray[i] == 0)
		{
			return FALSE;
		}
	}

	return FALSE;
}

BOOLEAN
NTAPI
FailedOperateMemoryAddressAdd(UINT64 TargetBaseAddress)
{
	for (int i = 0; i < KD_SYMBOLS_MAX; i++)
	{
		if (FailedOperateMemoryAddressArray[i] == TargetBaseAddress)
		{
			return TRUE;
		}

		if (FailedOperateMemoryAddressArray[i] == 0)
		{
			FailedOperateMemoryAddressArray[i] = TargetBaseAddress;
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN
NTAPI
KdpReadVirtualMemoryHook(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{

	BOOLEAN needhook = FALSE;
	PDBGKD_READ_MEMORY64 ReadMemory = &State->u.ReadMemory;
	ULONG Length = ReadMemory->TransferCount;
	if (!LowCheckMemoryAddr(ReadMemory->TargetBaseAddress) || Length == 0)
	{
		FailedOperateMemoryAddressReport(State, Data, Context);
		needhook = TRUE;
		return needhook;
	}
	if (FailedOperateMemoryAddressExsits(ReadMemory->TargetBaseAddress))
	{
		FailedOperateMemoryAddressReport(State, Data, Context);
		needhook = TRUE;
		return needhook;
	}


	FailedOperateMemoryCount++;



	if (FailedOperateMemoryAddress1 == 0)
	{
		FailedOperateMemoryAddress1 = ReadMemory->TargetBaseAddress;
	}
	else
	{
		if (FailedOperateMemoryAddress2 == 0)
		{
			FailedOperateMemoryAddress2 = ReadMemory->TargetBaseAddress;
		}
	}

	if ((FailedOperateMemoryAddress1 == ReadMemory->TargetBaseAddress && FailedOperateMemoryAddress2 == ReadMemory->TargetBaseAddress) || FailedOperateMemoryCount > 5)
	{
		FailedOperateMemoryAddressAdd(ReadMemory->TargetBaseAddress);
		FailedOperateMemoryAddressReport(State, Data, Context);
		needhook = TRUE;
	}
	return needhook;

}

VOID
NTAPI
KdpReadVirtualMemory(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	PDBGKD_READ_MEMORY64 ReadMemory = &State->u.ReadMemory;
	STRING Header;
	ULONG Length = ReadMemory->TransferCount;
	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	//ASSERT(Data->Length == 0);

	if (Data->Buffer == NULL)
	{
		KdpDprintf(L"KdpReadVirtualMemory Data->Buffer is NULL ReadMemory->ActualBytesRead==0 TargetBaseAddress %p\r\n", ReadMemory->TargetBaseAddress);
		return;
	}


	/* Validate length */
	if (Length > (PACKET_MAX_SIZE - sizeof(DBGKD_MANIPULATE_STATE64)))
	{
		/* Overflow, set it to maximum possible */
		Length = PACKET_MAX_SIZE - sizeof(DBGKD_MANIPULATE_STATE64);
	}

	if (Length > 0&&KdpReadVirtualMemoryMap(Data, ReadMemory->TargetBaseAddress, Length, Context))
	{
		ReadMemory->ActualBytesRead = Length;
		Data->Length = (USHORT)Length;
		KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			&Header,
			Data,
			&KdpContext);
		if (ForceConsoleOutput)
		{
			KdpDprintf(L"KdpReadVirtualMemory UefiMemoryPresent TRUE TargetBaseAddress %p\r\n", ReadMemory->TargetBaseAddress);
		}
		return;
	}


	if (Length == 0|| ReadMemory->TargetBaseAddress==0 || !UefiMemoryPresent(ReadMemory->TargetBaseAddress, Length) || !HvMemoryReadPresent(ReadMemory->TargetBaseAddress))
	{
		if (Length)
		{
			//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, CurrentPacketId);
			KdpZeroMemory(Data->Buffer, Length);
		}

		State->ReturnStatus = STATUS_SUCCESS;

		/* Return the actual length read */
		ReadMemory->ActualBytesRead = Length;
		Data->Length = (USHORT)Length;

		/* Send the packet */
		KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			&Header,
			Data,
			&KdpContext);
		FailedOperateMemoryAddress2 = 0;
		FailedOperateMemoryAddress1 = 0;
		FailedOperateMemoryCount = 0;
		if (ForceConsoleOutput)
		{
			KdpDprintf(L"KdpReadVirtualMemory UefiMemoryPresent FALSE TargetBaseAddress %p\r\n", ReadMemory->TargetBaseAddress);

		}

		return;
	}



	/* Do the read */
	KdpMoveMemory((void*)Data->Buffer, (void*)ReadMemory->TargetBaseAddress, Length);







	State->ReturnStatus = STATUS_SUCCESS;
	if (ForceConsoleOutput)
	{
		if (mSyntheticSymbolInfo[1].SymbolInfo.BaseOfDll && ReadMemory->TargetBaseAddress > (UINT64)mSyntheticSymbolInfo[1].SymbolInfo.BaseOfDll && ReadMemory->TargetBaseAddress < ((UINT64)mSyntheticSymbolInfo[1].SymbolInfo.BaseOfDll + mSyntheticSymbolInfo[1].SymbolInfo.SizeOfImage))
		{
			KdpDprintf(L"KdpReadVirtualMemory mSyntheticSymbolInfo TargetBaseAddress %p ok\r\n", ReadMemory->TargetBaseAddress);
		}
	}

	/* Return the actual length read */
	ReadMemory->ActualBytesRead = Length;
	Data->Length = (USHORT)Length;
	if (ReadMemory->ActualBytesRead == 0)
	{
		Length = ReadMemory->TransferCount;

		KdpDprintf(L"KdpReadVirtualMemory UefiMemoryPresent FALSE ReadMemory->ActualBytesRead==ReadMemory->TransferCount==0 TargetBaseAddress %p\r\n", ReadMemory->TargetBaseAddress);
		KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, CurrentPacketId);
		return;

		/*
		ReadMemory->ActualBytesRead = Length;
		Data->Length = (USHORT)Length;
		KdpZeroMemory(Data->Buffer, Length);
		/* Send the packet #1#
		KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			&Header,
			Data,
			&KdpContext);

		if (TRUE)
		{
			KdpDprintf(L"KdpReadVirtualMemory UefiMemoryPresent FALSE ReadMemory->ActualBytesRead==0 TargetBaseAddress %p\r\n", ReadMemory->TargetBaseAddress);

		}

		return;*/

	}
	else {


		FailedOperateMemoryAddress2 = 0;
		FailedOperateMemoryAddress1 = 0;
		FailedOperateMemoryCount = 0;
		/* Send the packet */
		KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			&Header,
			Data,
			&KdpContext);
		if (ForceConsoleOutput)
		{
			KdpDprintf(L"KdpReadVirtualMemory UefiMemoryPresent TRUE TargetBaseAddress %p\r\n", ReadMemory->TargetBaseAddress);
		}
	}
	return;
}

VOID
NTAPI
KdpWriteVirtualMemory(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	PDBGKD_WRITE_MEMORY64 WriteMemory = &State->u.WriteMemory;
	STRING Header;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	if (!UefiMemoryPresent(WriteMemory->TargetBaseAddress, Data->Length))
	{
		//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, CurrentPacketId);

		KdpZeroMemory(Data->Buffer, Data->Length);
		WriteMemory->ActualBytesWritten = Data->Length;
		State->ReturnStatus = STATUS_SUCCESS;
		KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			&Header,
			NULL,
			&KdpContext);

		if (ForceConsoleOutput)
		{
			KdpDprintf(L"KdpWriteVirtualMemory TargetBaseAddress FALSE %p\r\n", WriteMemory->TargetBaseAddress);
		}
		return;
	}
	/* Do the write */
	/*State->ReturnStatus = KdpCopyMemoryChunks(WriteMemory->TargetBaseAddress,
		Data->Buffer,
		Data->Length,
		0,
		MMDBG_COPY_UNSAFE |
		MMDBG_COPY_WRITE,
		&WriteMemory->ActualBytesWritten);*/

	KdpMoveMemory((void*)WriteMemory->TargetBaseAddress,
		(void*)Data->Buffer,
		Data->Length);



	State->ReturnStatus = STATUS_SUCCESS;

	/* Send the packet */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);

	if (ForceConsoleOutput)
	{
		KdpDprintf(L"KdpWriteVirtualMemory TargetBaseAddress TRUE %p\r\n", WriteMemory->TargetBaseAddress);
	}
	return;
}

VOID
NTAPI
KdpReadPhysicalMemory(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	PDBGKD_READ_MEMORY64 ReadMemory = &State->u.ReadMemory;
	STRING Header;
	ULONG Length = ReadMemory->TransferCount;
	ULONG Flags, CacheFlags;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	ASSERT(Data->Length == 0);

	if (KdpReadVirtualMemoryMap(Data, ReadMemory->TargetBaseAddress, Length, Context))
	{
		ReadMemory->ActualBytesRead = Length;
		Data->Length = (USHORT)Length;
		KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			&Header,
			Data,
			&KdpContext);
		if (ForceConsoleOutput)
		{
			KdpDprintf(L"KdpReadVirtualMemory UefiMemoryPresent TRUE TargetBaseAddress %p\r\n", ReadMemory->TargetBaseAddress);
		}
		return;
	}

	if (!UefiMemoryPresent(ReadMemory->TargetBaseAddress, Length))
	{
		//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, CurrentPacketId);
		KdpZeroMemory(Data->Buffer, Length);
		State->ReturnStatus = STATUS_SUCCESS;
		ReadMemory->ActualBytesRead = Length;
		Data->Length = (USHORT)Length;
		KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			&Header,
			NULL,
			&KdpContext);
		if (ForceConsoleOutput)
		{
			KdpDprintf(L"KdpReadPhysicalMemory UefiMemoryPresent FALSE TargetBaseAddress %p\r\n", ReadMemory->TargetBaseAddress);
		}
		return;
	}
	/* Validate length */
	if (Length > (PACKET_MAX_SIZE - sizeof(DBGKD_MANIPULATE_STATE64)))
	{
		/* Overflow, set it to maximum possible */
		Length = PACKET_MAX_SIZE - sizeof(DBGKD_MANIPULATE_STATE64);
	}

	/* Start with the default flags */
	Flags = MMDBG_COPY_UNSAFE | MMDBG_COPY_PHYSICAL;

	/* Get the caching flags and check if a type is specified */
	CacheFlags = ReadMemory->ActualBytesRead;
	if (CacheFlags == DBGKD_CACHING_CACHED)
	{
		/* Cached */
		Flags |= MMDBG_COPY_CACHED;
	}
	else if (CacheFlags == DBGKD_CACHING_UNCACHED)
	{
		/* Uncached */
		Flags |= MMDBG_COPY_UNCACHED;
	}
	else if (CacheFlags == DBGKD_CACHING_WRITE_COMBINED)
	{
		/* Write Combined */
		Flags |= MMDBG_COPY_WRITE_COMBINED;
	}

	/* Do the read */
	/*State->ReturnStatus = KdpCopyMemoryChunks(ReadMemory->TargetBaseAddress,
		Data->Buffer,
		Length,
		0,
		Flags,
		&Length);
		*/
	KdpMoveMemory((void*)Data->Buffer, (void*)ReadMemory->TargetBaseAddress, Length);


	State->ReturnStatus = STATUS_SUCCESS;
	/* Return the actual length read */
	ReadMemory->ActualBytesRead = Length;
	Data->Length = (USHORT)Length;

	/* Send the packet */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		Data,
		&KdpContext);
	if (ForceConsoleOutput)
	{
		KdpDprintf(L"KdpReadPhysicalMemory UefiMemoryPresent TRUE TargetBaseAddress %p\r\n", ReadMemory->TargetBaseAddress);
	}
	return;
}

VOID
NTAPI
KdpWritePhysicalMemory(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	PDBGKD_WRITE_MEMORY64 WriteMemory = &State->u.WriteMemory;
	STRING Header;
	ULONG Flags, CacheFlags;
	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	if (!UefiMemoryPresent(WriteMemory->TargetBaseAddress, Data->Length))
	{

		//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, CurrentPacketId);
		WriteMemory->ActualBytesWritten = Data->Length;
		State->ReturnStatus = STATUS_SUCCESS;
		KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			&Header,
			NULL,
			&KdpContext);

		if (ForceConsoleOutput)
		{
			KdpDprintf(L"KdpWritePhysicalMemory TargetBaseAddress FALSE %p\r\n", WriteMemory->TargetBaseAddress);
		}
		return;
	}


	/* Start with the default flags */
	Flags = MMDBG_COPY_UNSAFE | MMDBG_COPY_WRITE | MMDBG_COPY_PHYSICAL;

	/* Get the caching flags and check if a type is specified */
	CacheFlags = WriteMemory->ActualBytesWritten;
	if (CacheFlags == DBGKD_CACHING_CACHED)
	{
		/* Cached */
		Flags |= MMDBG_COPY_CACHED;
	}
	else if (CacheFlags == DBGKD_CACHING_UNCACHED)
	{
		/* Uncached */
		Flags |= MMDBG_COPY_UNCACHED;
	}
	else if (CacheFlags == DBGKD_CACHING_WRITE_COMBINED)
	{
		/* Write Combined */
		Flags |= MMDBG_COPY_WRITE_COMBINED;
	}

	/* Do the write */
	State->ReturnStatus = KdpCopyMemoryChunks(WriteMemory->TargetBaseAddress,
		Data->Buffer,
		Data->Length,
		0,
		Flags,
		&WriteMemory->ActualBytesWritten);

	/* Send the packet */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);

	if (ForceConsoleOutput)
	{
		KdpDprintf(L"KdpWritePhysicalMemory TargetBaseAddress TRUE %p\r\n", WriteMemory->TargetBaseAddress);
	}

	return;
}

VOID
NTAPI
KdpReadControlSpace(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context, DEBUG_CPU_CONTEXT* CpuContext)
{
	PDBGKD_READ_MEMORY64 ReadMemory = &State->u.ReadMemory;
	STRING Header;
	ULONG Length;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	ASSERT(Data->Length == 0);

	/* Check the length requested */
	Length = ReadMemory->TransferCount;
	if (Length > (PACKET_MAX_SIZE - sizeof(DBGKD_MANIPULATE_STATE64)))
	{
		/* Use maximum allowed */
		Length = PACKET_MAX_SIZE - sizeof(DBGKD_MANIPULATE_STATE64);
	}
	KdpZeroMemory(
		Data->Buffer,
		Length);

	/* Call the internal routine*/
	KdpSysReadControlSpace(State->Processor,
		ReadMemory->TargetBaseAddress,
		Data->Buffer,
		Length,
		&Length, CpuContext);

	State->ReturnStatus = STATUS_SUCCESS;



	/* Return the actual length read */
	ReadMemory->ActualBytesRead = ReadMemory->TransferCount;
	Data->Length = (USHORT)ReadMemory->TransferCount;

	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		Data,
		&KdpContext);
	return;
}

VOID
NTAPI
KdpWriteControlSpace(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context, DEBUG_CPU_CONTEXT* CpuContext)
{
	PDBGKD_WRITE_MEMORY64 WriteMemory = &State->u.WriteMemory;
	STRING Header;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	WriteMemory->ActualBytesWritten = WriteMemory->TransferCount;
	KdpZeroMemory(Data->Buffer,
		Data->Length
	);
	/* Call the internal routine */
	/*State->ReturnStatus = KdpSysWriteControlSpace(State->Processor,
		WriteMemory->TargetBaseAddress,
		Data->Buffer,
		Data->Length,
		&WriteMemory->ActualBytesWritten);*/

	State->ReturnStatus = STATUS_SUCCESS;
	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		Data,
		&KdpContext);
	return;
}

VOID
NTAPI
KdpGetContext(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	STRING Header;
	PCONTEXT TargetContext = Context;

	/* Setup the header #1#
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	/*
	ASSERT(Data->Length == 0);

	/* Make sure that this is a valid request #1#
	if (State->Processor < KeNumberProcessors)
	{
		/* Check if the request is for this CPU #1#
		if (State->Processor == KeGetCurrentPrcb()->Number)
		{
			/* We're just copying our own context #1#
			TargetContext = Context;
		}
		else
		{
			/* Get the context from the PRCB array #1#
			TargetContext = &KiProcessorBlock[State->Processor]->
				ProcessorState.ContextFrame;
		}

		/* Copy it over to the debugger #1#
		KdpMoveMemory(Data->Buffer,
			TargetContext,
			sizeof(CONTEXT));
		Data->Length = sizeof(CONTEXT);

		/* Let the debugger set the context now #1#
		KdpContextSent = TRUE;

		/* Finish up #1#
		State->ReturnStatus = STATUS_SUCCESS;
	}
	else
	{
		/* Invalid request #1#
		State->ReturnStatus = STATUS_UNSUCCESSFUL;
	}*/

	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;

	KdpMoveMemory(Data->Buffer,
		TargetContext,
		sizeof(CONTEXT));
	Data->Length = sizeof(CONTEXT);

	/* Let the debugger set the context now*/
	KdpContextSent = TRUE;

	/* Finish up */
	State->ReturnStatus = STATUS_SUCCESS;

	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		Data,
		&KdpContext);
	return;
}

VOID
NTAPI
KdpSetContext(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context, PDEBUG_CPU_CONTEXT CpuContext)
{

	STRING Header;
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;

	KdpZeroMemory(Header.Buffer, Header.Length);

	State->ApiNumber = DbgKdSetContextApi;
	//ASSERT(Data->Length == sizeof(CONTEXT));
	if (Data->Length == sizeof(CONTEXT))
	{
		PCONTEXT TargetContext = Context;
		/*


		/* Setup the header #1#


		/* Make sure that this is a valid request #1#
		if ((State->Processor < KeNumberProcessors) &&
			(KdpContextSent))
		{
			/* Check if the request is for this CPU #1#
			if (State->Processor == KeGetCurrentPrcb()->Number)
			{
				/* We're just copying our own context #1#
				TargetContext = Context;
			}
			else
			{
				/* Get the context from the PRCB array #1#
				TargetContext = &KiProcessorBlock[State->Processor]->
					ProcessorState.ContextFrame;
			}

			/* Copy the new context to it #1#
			KdpMoveMemory(TargetContext,
				Data->Buffer,
				sizeof(CONTEXT));

			/* Finish up #1#
			State->ReturnStatus = STATUS_SUCCESS;
		}
		else
		{
			/* Invalid request #1#
			State->ReturnStatus = STATUS_UNSUCCESSFUL;
		}*/
		if (TargetContext)
		{
			KdpMoveMemory(TargetContext,
				Data->Buffer,
				sizeof(CONTEXT));
			if (CpuContext)
			{
				//WindbgCtx2UefiCtx(TargetContext, CpuContext);
			}
		}
	}
	else
	{
		KdpDprintf(L"Data->Length == sizeof(CONTEXT) %08x %08x check  failed\r\n", Data->Length, sizeof(CONTEXT));
	}


	/* Finish up */
	State->ReturnStatus = STATUS_SUCCESS;
	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);

	if (ForceConsoleOutput)
	{
		KdpDprintf(L"KdpSetContext\r\n");
	}
	return;
}

VOID
NTAPI
KdpGetContextEx(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	STRING Header;
	PDBGKD_CONTEXT_EX ContextEx;
	PCONTEXT TargetContext = Context;
	ContextEx = &State->u.ContextEx;
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;

	if (ContextEx->Offset > KDP_MSG_BUFFER_SIZE || ContextEx->ByteCount > KDP_MSG_BUFFER_SIZE)
	{
		KdpDprintf(L"error KdpGetContextEx Offset %08x ByteCount %08x\r\n", ContextEx->Offset, ContextEx->ByteCount);
		ContextEx->BytesCopied = ContextEx->ByteCount = 0;
		Data->Length = (UINT16)ContextEx->BytesCopied;
		/* Let the debugger set the context now  */
		KdpContextSent = TRUE;

		State->ReturnStatus = STATUS_SUCCESS;

		/* Send the reply */
		KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			&Header,
			Data,
			&KdpContext);
		return;
	}


	if (!TargetContext)
	{
		//KdpZeroMemory(Data->Buffer, ContextEx->ByteCount);
		ContextEx->BytesCopied = ContextEx->ByteCount;
		Data->Length = (UINT16)ContextEx->BytesCopied;
		/* Let the debugger set the context now  */
		KdpContextSent = TRUE;

		State->ReturnStatus = STATUS_SUCCESS;

		/* Send the reply */
		KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			&Header,
			Data,
			&KdpContext);
		return;
	}
	/*
	ASSERT(Data->Length == 0);

	/* Get our struct #1#
	ContextEx = &State->u.ContextEx;

	/* Set up the header #1#


	/* Make sure that this is a valid request #1#
	if ((State->Processor < KeNumberProcessors) &&
		(ContextEx->Offset + ContextEx->ByteCount) <= sizeof(CONTEXT))
	{
		/* Check if the request is for this CPU #1#
		if (State->Processor == KeGetCurrentPrcb()->Number)
		{
			/* We're just copying our own context #1#
			TargetContext = Context;
		}
		else
		{
			/* Get the context from the PRCB array #1#
			TargetContext = &KiProcessorBlock[State->Processor]->
				ProcessorState.ContextFrame;
		}

		/* Copy what is requested #1#
		KdpMoveMemory(Data->Buffer,
			(PVOID)((ULONG_PTR)TargetContext + ContextEx->Offset),
			ContextEx->ByteCount);

		/* KD copies all #1#
		Data->Length = ContextEx->BytesCopied = ContextEx->ByteCount;

		/* Let the debugger set the context now #1#
		KdpContextSent = TRUE;

		/* Finish up #1#
		State->ReturnStatus = STATUS_SUCCESS;
	}
	else
	{
		/* Invalid request #1#
		ContextEx->BytesCopied = 0;
		State->ReturnStatus = STATUS_UNSUCCESSFUL;
	}
	*/

	if (ContextEx->ByteCount > sizeof(CONTEXT) - ContextEx->Offset)
	{
		ContextEx->ByteCount = sizeof(CONTEXT) - ContextEx->Offset;
	}

	// Copy what is requested #1#
	KdpMoveMemory((void*)Data->Buffer,
		(void*)((UINT64)TargetContext + ContextEx->Offset),
		ContextEx->ByteCount);

	/* KD copies all  */
	ContextEx->BytesCopied = ContextEx->ByteCount;
	Data->Length = (UINT16)ContextEx->BytesCopied;
	/* Let the debugger set the context now  */
	KdpContextSent = TRUE;

	State->ReturnStatus = STATUS_SUCCESS;


	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		Data,
		&KdpContext);
	return;
}

VOID
NTAPI
KdpSetContextEx(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context, PDEBUG_CPU_CONTEXT CpuContext)
{
	STRING Header;
	PDBGKD_CONTEXT_EX ContextEx = &State->u.ContextEx;
	PCONTEXT TargetContext = Context;
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	KdpContextSent = TRUE;
	/*if (!TargetContext)
	{
		KdpZeroMemory(Data->Buffer, ContextEx->ByteCount);
		ContextEx->BytesCopied = ContextEx->ByteCount;
		/* Let the debugger set the context now  #1#
		KdpContextSent = TRUE;

		State->ReturnStatus = STATUS_SUCCESS;
		/* Send the reply #1#
		KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			&Header,
			Data,
			&KdpContext);
		if (ForceConsoleOutput)
		{
			KdpDprintf(L"KdpSetContextEx\r\n");
		}
		return;
	}*/
	/* Get our struct */
	/*ContextEx = &State->u.ContextEx;
	ASSERT(Data->Length == ContextEx->ByteCount);

	/* Set up the header #1#
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;

	/* Make sure that this is a valid request #1#
	if ((State->Processor < KeNumberProcessors) &&
		((ContextEx->Offset + ContextEx->ByteCount) <= sizeof(CONTEXT)) &&
		(KdpContextSent))
	{
		/* Check if the request is for this CPU #1#
		if (State->Processor == KeGetCurrentPrcb()->Number)
		{
			/* We're just copying our own context #1#
			TargetContext = Context;
		}
		else
		{
			/* Get the context from the PRCB array #1#
			TargetContext = &KiProcessorBlock[State->Processor]->
				ProcessorState.ContextFrame;
		}

		/* Copy what is requested #1#


		/* KD copies all #1#
		ContextEx->BytesCopied = ContextEx->ByteCount;

		/* Finish up #1#
		State->ReturnStatus = STATUS_SUCCESS;
	}
	else
	{
		/* Invalid request #1#
		ContextEx->BytesCopied = 0;
		State->ReturnStatus = STATUS_UNSUCCESSFUL;
	}*/
	if (TargetContext && ContextEx->ByteCount + ContextEx->Offset <= sizeof(CONTEXT))
	{
		KdpMoveMemory((PVOID)((UINT64)TargetContext + ContextEx->Offset),
			Data->Buffer,
			ContextEx->ByteCount);
		if (CpuContext)
		{
			//WindbgCtx2UefiCtx(TargetContext, CpuContext);
		}
	}

	/*
	KdpMoveMemory((PVOID)((ULONG_PTR)TargetContext + ContextEx->Offset),
		Data->Buffer,
		ContextEx->ByteCount);

	/* KD copies all #1#
	ContextEx->BytesCopied = ContextEx->ByteCount;


		*/

	State->ReturnStatus = STATUS_SUCCESS;
	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);

	if (ForceConsoleOutput)
	{
		KdpDprintf(L"KdpSetContextEx\r\n");
	}
	return;
}

VOID
NTAPI
KdpCauseBugCheck(IN PDBGKD_MANIPULATE_STATE64 State)
{
	/* Crash with the special code */
	//KeBugCheck(MANUALLY_INITIATED_CRASH);
	return;
}

VOID
NTAPI
KdpReadMachineSpecificRegister(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	STRING Header;
	PDBGKD_READ_WRITE_MSR ReadMsr = &State->u.ReadWriteMsr;
	LARGE_INTEGER MsrValue;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	ASSERT(Data->Length == 0);

	/* Call the internal routine */
	State->ReturnStatus = KdpSysReadMsr(ReadMsr->Msr,
		&MsrValue);

	/* Return the data */
	ReadMsr->DataValueLow = MsrValue.u.LowPart;
	ReadMsr->DataValueHigh = MsrValue.u.HighPart;

	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
	return;
}

VOID
NTAPI
KdpWriteMachineSpecificRegister(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	STRING Header;
	PDBGKD_READ_WRITE_MSR WriteMsr = &State->u.ReadWriteMsr;
	LARGE_INTEGER MsrValue;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	ASSERT(Data->Length == 0);

	/* Call the internal routine */
	MsrValue.u.LowPart = WriteMsr->DataValueLow;
	MsrValue.u.HighPart = WriteMsr->DataValueHigh;
	State->ReturnStatus = KdpSysWriteMsr(WriteMsr->Msr,
		&MsrValue);

	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
	return;
}

VOID
NTAPI
KdpGetBusData(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	STRING Header;
	PDBGKD_GET_SET_BUS_DATA GetBusData = &State->u.GetSetBusData;
	ULONG Length;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	ASSERT(Data->Length == 0);

	/* Check the length requested */
	Length = GetBusData->Length;
	if (Length > (PACKET_MAX_SIZE - sizeof(DBGKD_MANIPULATE_STATE64)))
	{
		/* Use maximum allowed */
		Length = PACKET_MAX_SIZE - sizeof(DBGKD_MANIPULATE_STATE64);
	}

	/* Call the internal routine */
	/*State->ReturnStatus = KdpSysReadBusData(GetBusData->BusDataType,
		GetBusData->BusNumber,
		GetBusData->SlotNumber,
		GetBusData->Offset,
		Data->Buffer,
		Length,
		&Length);*/
	State->ReturnStatus = 0;

	/* Return the actual length read */
	GetBusData->Length = Length;
	Data->Length = (USHORT)Length;

	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		Data,
		&KdpContext);
	return;
}

VOID
NTAPI
KdpSetBusData(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	STRING Header;
	//PDBGKD_GET_SET_BUS_DATA SetBusData = &State->u.GetSetBusData;
	//ULONG Length;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;

	/* Call the internal routine */
	/*State->ReturnStatus = KdpSysWriteBusData(SetBusData->BusDataType,
		SetBusData->BusNumber,
		SetBusData->SlotNumber,
		SetBusData->Offset,
		Data->Buffer,
		SetBusData->Length,
		&Length);*/
	State->ReturnStatus = 0;

	/* Return the actual length written */
	//SetBusData->Length = Length;

	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
}

VOID
NTAPI
KdpReadIoSpace(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	STRING Header;
	PDBGKD_READ_WRITE_IO64 ReadIo = &State->u.ReadWriteIo;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	ASSERT(Data->Length == 0);

	/*
	 * Clear the value so 1 or 2 byte reads
	 * don't leave the higher bits unmodified
	 */
	ReadIo->DataValue = 0;

	/* Call the internal routine */
	State->ReturnStatus = KdpSysReadIoSpace(Isa,
		0,
		1,
		ReadIo->IoAddress,
		&ReadIo->DataValue,
		ReadIo->DataSize,
		&ReadIo->DataSize);
	//State->ReturnStatus = 0;
	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
	return;
}

VOID
NTAPI
KdpWriteIoSpace(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	STRING Header;
	PDBGKD_READ_WRITE_IO64 WriteIo = &State->u.ReadWriteIo;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	ASSERT(Data->Length == 0);

	/* Call the internal routine */
	State->ReturnStatus = KdpSysWriteIoSpace(Isa,
		0,
		1,
		WriteIo->IoAddress,
		&WriteIo->DataValue,
		WriteIo->DataSize,
		&WriteIo->DataSize);
	//State->ReturnStatus = 0;
	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
}

VOID
NTAPI
KdpReadIoSpaceExtended(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	STRING Header;
	PDBGKD_READ_WRITE_IO_EXTENDED64 ReadIoExtended = &State->u.
		ReadWriteIoExtended;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	ASSERT(Data->Length == 0);

	/*
	 * Clear the value so 1 or 2 byte reads
	 * don't leave the higher bits unmodified
	 */
	ReadIoExtended->DataValue = 0;

	/* Call the internal routine */
	State->ReturnStatus = KdpSysReadIoSpace(ReadIoExtended->InterfaceType,
		ReadIoExtended->BusNumber,
		ReadIoExtended->AddressSpace,
		ReadIoExtended->IoAddress,
		&ReadIoExtended->DataValue,
		ReadIoExtended->DataSize,
		&ReadIoExtended->DataSize);
	//State->ReturnStatus = STATUS_SUCCESS;

	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
}

VOID
NTAPI
KdpWriteIoSpaceExtended(IN PDBGKD_MANIPULATE_STATE64 State,
	IN PSTRING Data,
	IN PCONTEXT Context)
{
	STRING Header;
	PDBGKD_READ_WRITE_IO_EXTENDED64 WriteIoExtended = &State->u.
		ReadWriteIoExtended;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;
	ASSERT(Data->Length == 0);

	/* Call the internal routine */
	State->ReturnStatus = KdpSysWriteIoSpace(WriteIoExtended->InterfaceType,
		WriteIoExtended->BusNumber,
		WriteIoExtended->AddressSpace,
		WriteIoExtended->IoAddress,
		&WriteIoExtended->DataValue,
		WriteIoExtended->DataSize,
		&WriteIoExtended->DataSize);
	//State->ReturnStatus = STATUS_SUCCESS;
	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
}

VOID
NTAPI
KdpCheckLowMemory(IN PDBGKD_MANIPULATE_STATE64 State)
{
	STRING Header;

	/* Setup the header */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;

	/* Call the internal routine */
	State->ReturnStatus = KdpSysCheckLowMemory(MMDBG_COPY_UNSAFE);

	/* Send the reply */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
}

VOID
NTAPI
KdpNotSupported(IN PDBGKD_MANIPULATE_STATE64 State)
{
	STRING Header;

	/* Set failure */
	State->ReturnStatus = STATUS_UNSUCCESSFUL;

	/* Setup the packet */
	Header.Length = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)State;

	/* Send it */
	KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
		&Header,
		NULL,
		&KdpContext);
}

KCONTINUE_STATUS
NTAPI KdpSymbolReportSynthetic() {
	KCONTINUE_STATUS ret = ContinueSuccess;
	if (ReportSynthetic <= 1 && mSyntheticSymbolInfo[0].SymbolInfo.BaseOfDll != NULL)
	{
		ReportSynthetic++;

		if (ReportSynthetic == 0)
		{
			CurrentPacketId = SYNC_PACKET_ID | INITIAL_PACKET_ID;
		}
		else
		{
			CurrentPacketId = INITIAL_PACKET_ID;
		}

		hvwcscpy(mSyntheticSymbolInfo[0].SymbolPathBuffer, L"\\SystemRoot\\system32\\ntoskrnl.exe");
		ret = ContinueProcessorReselected;
	}

	PCONTEXT Context = NULL;
	STRING Data = { 0 };
	//Data.Length = StrLen(mSyntheticSymbolInfo[0].SymbolPathBuffer);
	//Data.Length = AsciiStrSize(KdpMessageBuffer);
	//UnicodeStrToAsciiStrS(mSyntheticSymbolInfo[0].SymbolPathBuffer, KdpMessageBuffer, KD_SYMBOLS_MAX);
	Data.Length = (UINT16)w2s(mSyntheticSymbolInfo[0].SymbolPathBuffer, KdpMessageBuffer);

	UINT64 lenchk = AsciiStrSize(KdpMessageBuffer);
	if (lenchk == 0)
	{
		KdpDprintf(L"KdInitSystem Failed\n");
		return ret;
	}

	Data.Buffer = KdpMessageBuffer;
	Data.MaximumLength = Data.Length;
	KdpSymbol((PSTRING)&Data,
		(PKD_SYMBOLS_INFO)&mSyntheticSymbolInfo[0].SymbolInfo,
		FALSE,
		0,
		Context,
		NULL,
		NULL,
		NULL, TRUE);
	//KdpDprintf(L"KdpSymbolReportSynthetic Success\n");
	return ret;
}
KCONTINUE_STATUS
NTAPI
KdpReceiveManipulateStateApi(PDBGKD_MANIPULATE_STATE64 PManipulateState, PSTRING PHeader, PSTRING PData, PCONTEXT Context, PDEBUG_CPU_CONTEXT CpuContext)
{

	/* Now check what API we got */
	switch (PManipulateState->ApiNumber)
	{
	case DbgKdReadVirtualMemoryApi:

		/* Read virtual memory */
		//KdpReadVirtualMemoryHook(PManipulateState, PData, Context);
		KdpReadVirtualMemory(PManipulateState, PData, Context);
		break;

	case DbgKdWriteVirtualMemoryApi:

		/* Write virtual memory */
		KdpWriteVirtualMemory(PManipulateState, PData, Context);
		break;

	case DbgKdGetContextApi:

		/* Get the current context */
		KdpGetContext(PManipulateState, PData, Context);
		break;

	case DbgKdSetContextApi:

		/* Set a new context */
		KdpSetContext(PManipulateState, PData, Context, CpuContext);
		break;

	case DbgKdWriteBreakPointApi:

		/* Write the breakpoint */
		KdpWriteBreakpoint(PManipulateState, PData, Context);
		break;

	case DbgKdRestoreBreakPointApi:

		/* Restore the breakpoint */
		KdpRestoreBreakpoint(PManipulateState, PData, Context);
		break;

	case DbgKdContinueApi:
		//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, CurrentPacketId);
		/* Simply continue */
		return ContinueSuccess;
		//return NT_SUCCESS(ManipulateState.u.Continue.ContinueStatus);
		break;

	case DbgKdReadControlSpaceApi:

		/* Read control space */
		KdpReadControlSpace(PManipulateState, PData, Context, CpuContext);
		break;

	case DbgKdWriteControlSpaceApi:

		/* Write control space */
		KdpWriteControlSpace(PManipulateState, PData, Context, CpuContext);
		//return ContinueSuccess;
		break;

	case DbgKdReadIoSpaceApi:

		/* Read I/O Space */
		KdpReadIoSpace(PManipulateState, PData, Context);
		break;

	case DbgKdWriteIoSpaceApi:

		/* Write I/O Space */
		KdpWriteIoSpace(PManipulateState, PData, Context);
		break;

	case DbgKdRebootApi:

		/* Reboot the system */
	   // HalReturnToFirmware(HalRebootRoutine);
		break;

	case DbgKdContinueApi2:
		//KdpDprintf(L"DbgKdContinueApi2\r\n");
		KdpGetStateChange(PManipulateState, Context, CpuContext);
		KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, CurrentPacketId);

		//
		//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, Packet.PacketId);			
		/* Check if caller reports success */
		return ContinueSuccess;
		/*if (NT_SUCCESS(PManipulateState->u.Continue2.ContinueStatus))
		{
			/* Update the state #1#

			return ContinueSuccess;
		}
		else
		{
			/* Return an error #1#
			return ContinueError;
		}*/

	case DbgKdReadPhysicalMemoryApi:

		/* Read  physical memory */
		KdpReadPhysicalMemory(PManipulateState, PData, Context);
		break;

	case DbgKdWritePhysicalMemoryApi:

		/* Write  physical memory */
		KdpWritePhysicalMemory(PManipulateState, PData, Context);
		break;

	case DbgKdQuerySpecialCallsApi:
	case DbgKdSetSpecialCallApi:
	case DbgKdClearSpecialCallsApi:

		/* TODO */
		KdpDprintf(L"Special Call support is unimplemented!\n");
		KdpNotSupported(PManipulateState);
		break;

	case DbgKdSetInternalBreakPointApi:
	case DbgKdGetInternalBreakPointApi:

		/* TODO */
		KdpDprintf(L"Internal Breakpoint support is unimplemented!\n");
		KdpNotSupported(PManipulateState);
		break;

	case DbgKdReadIoSpaceExtendedApi:

		/* Read I/O Space */
		KdpReadIoSpaceExtended(PManipulateState, PData, Context);
		break;

	case DbgKdWriteIoSpaceExtendedApi:

		/* Write I/O Space */
		KdpWriteIoSpaceExtended(PManipulateState, PData, Context);
		break;

	case DbgKdGetVersionApi:

		/* Get version data */
		KdpGetVersion(PManipulateState);

		break;

	case DbgKdWriteBreakPointExApi:

		/* Write the breakpoint and check if it failed */
		if (!NT_SUCCESS(KdpWriteBreakPointEx(PManipulateState,
			PData,
			Context)))
		{
			/* Return an error */
			return ContinueError;
		}
		break;

	case DbgKdRestoreBreakPointExApi:

		/* Restore the breakpoint */
		KdpRestoreBreakPointEx(PManipulateState, PData, Context);
		break;

	case DbgKdCauseBugCheckApi:

		/* Crash the system */
		KdpCauseBugCheck(PManipulateState);
		break;

	case DbgKdSwitchProcessor:

		/* TODO */
		KdpDprintf(L"Processor Switch support is unimplemented!\n");
		KdpNotSupported(PManipulateState);
		break;

	case DbgKdPageInApi:

		/* TODO */
		KdpDprintf(L"Page-In support is unimplemented!\n");
		KdpNotSupported(PManipulateState);
		break;

	case DbgKdReadMachineSpecificRegister:

		/* Read from the specified MSR */
		KdpReadMachineSpecificRegister(PManipulateState, PData, Context);
		break;

	case DbgKdWriteMachineSpecificRegister:

		/* Write to the specified MSR */
		KdpWriteMachineSpecificRegister(PManipulateState, PData, Context);
		break;

	case DbgKdSearchMemoryApi:

		/* Search memory */
		KdpSearchMemory(PManipulateState, PData, Context);
		break;

	case DbgKdGetBusDataApi:

		/* Read from the bus */
		KdpGetBusData(PManipulateState, PData, Context);
		break;

	case DbgKdSetBusDataApi:

		/* Write to the bus */
		KdpSetBusData(PManipulateState, PData, Context);
		break;

	case DbgKdCheckLowMemoryApi:

		/* Check for memory corruption in the lower 4 GB */
		KdpCheckLowMemory(PManipulateState);
		break;

	case DbgKdClearAllInternalBreakpointsApi:

		/* Just clear the counter */
		KdpNumInternalBreakpoints = 0;
		//KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, CurrentPacketId);
		break;

	case DbgKdFillMemoryApi:

		/* Fill memory */
		KdpFillMemory(PManipulateState, PData, Context);
		break;

	case DbgKdQueryMemoryApi:

		/* Query memory */
		KdpQueryMemory(PManipulateState, Context);
		break;

	case DbgKdSwitchPartition:

		/* TODO */
		KdpDprintf(L"Partition Switch support is unimplemented!\n");
		KdpNotSupported(PManipulateState);
		break;

	case DbgKdWriteCustomBreakpointApi:

		/* Write the customized breakpoint */
		KdpWriteCustomBreakpoint(PManipulateState, PData, Context);
		break;

	case DbgKdGetContextExApi:

		/* Extended Context Get */
		KdpGetContextEx(PManipulateState, PData, Context);
		break;

	case DbgKdSetContextExApi:

		/* Extended Context Set */
		KdpSetContextEx(PManipulateState, PData, Context, CpuContext);
		break;

		/* Unsupported Messages */
	default:

		/* Send warning */
		KdpDprintf(L"Received Unrecognized API 0x%lx\n", PManipulateState->ApiNumber);
		KdpSendControlPacket(PACKET_TYPE_KD_RESEND, 0);
		return ContinueError;
		/* Setup an empty message, with failure */
		/*PData->Length = 0;
		PManipulateState->ReturnStatus = STATUS_UNSUCCESSFUL;

		/* Send it #1#
		KdSendPacket(PACKET_TYPE_KD_STATE_MANIPULATE,
			PHeader,
			PData,
			&KdpContext);
		break;*/
	}
	return ContinueProcessorReselected;

}



KCONTINUE_STATUS
NTAPI
KdpSendWaitContinue(IN ULONG PacketType,
	IN PSTRING SendHeader,
	IN PSTRING SendData OPTIONAL,
	IN OUT PCONTEXT Context, DEBUG_CPU_CONTEXT* CpuContext)
{
	KdpContextSyncPacket = TRUE;
	KDSTATUS	apiretcode = ContinueProcessorReselected;
	STRING Data, Header;
	DBGKD_MANIPULATE_STATE64 ManipulateState;
	ULONG Length;
	KDSTATUS RecvCode;
	//UINT64 KdpContext = 0;
	/* Setup the Manipulate State structure */
	Header.MaximumLength = sizeof(DBGKD_MANIPULATE_STATE64);
	Header.Buffer = (PCHAR)&ManipulateState;
	Data.MaximumLength = (USHORT)sizeof(KdpPathSafeBuffer);
	Data.Buffer = KdpPathSafeBuffer;
	int fatalchk = 0;
	/*
	 * Reset the context state to ensure the debugger has received
	 * the current context before it sets it.
	 */
	KdpContextSent = FALSE;

SendPacket:
	/* Send the Packet */
	RecvCode = KdSendPacket(PacketType, SendHeader, SendData, &KdpContext);
	if (RecvCode == KdPacketNeedsResend) {

		/*if (PacketType == PACKET_TYPE_KD_STATE_CHANGE64)
		{
			KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
			return ContinueSuccess;
		}*/
		/*KdpDprintf(L"fatalchk KdSendPacket\r\n");
		if (fatalchk == 1)
		{

		}
		fatalchk = 0;*/
		goto SendPacket;
	}
	/* If the debugger isn't present anymore, just return success */
	if (KdDebuggerNotPresent) return ContinueSuccess;

	/* Main processing Loop */
	while (TRUE)
	{
		/* Receive Loop */
		while (TRUE)
		{
			KdpContext.KdpControlCPending = FALSE;
			/* Wait to get a reply to our packet */
			RecvCode = KdReceivePacket(PACKET_TYPE_KD_STATE_MANIPULATE,
				&Header,
				&Data,
				&Length,
				&KdpContext);

			/* If we got a resend request, do it */
			if (RecvCode == KdPacketNeedsResend) {

				/*if (PacketType == PACKET_TYPE_KD_STATE_CHANGE64)
				{
					KdpSendControlPacket(PACKET_TYPE_KD_ACKNOWLEDGE, 0);
					return ContinueSuccess;
				}*/
				///KdpDprintf(L"fatalchk KdReceivePacket re SendPacket\r\n");
				fatalchk = 1;
				goto SendPacket;
			}
			else if (RecvCode == KDP_PACKET_TIMEOUT)
			{
				KdpContextSyncPacket = FALSE;
				return KDP_PACKET_TIMEOUT;

			}
			else if (RecvCode == KDP_PACKET_RECEIVED)
			{

				break;
			}
			else
			{
				continue;
			}
		};
		//注意
		//CurrentPacketId &= ~SYNC_PACKET_ID;

		/*if(CurrentPacketId==0x80800001)
		{
			//CurrentPacketId ^= 1;

			CurrentPacketId = 0x80800000;
		}else
		{
			CurrentPacketId = 0x80800001;
		}
		*/

		//
		//apiretcode = KdpReceiveManipulateStateApi(&ManipulateState, &Header, &Data, Context, CpuContext);
		apiretcode = KdpReceiveManipulateStateApi((PDBGKD_MANIPULATE_STATE64)Header.Buffer, &Header, &Data, Context, CpuContext);
		if (Header.Buffer)
		{
			FreePool(Header.Buffer);
			Header.Buffer = NULL;
		}
		if (Data.Buffer)
		{
			FreePool(Data.Buffer);
			Data.Buffer = NULL;
		}

		if (apiretcode == ContinueError)
		{
			continue;
		}
		else if (apiretcode != ContinueProcessorReselected)
		{
			break;
		}
		else
		{
			continue;
		}
	}

	KdpContextSyncPacket = FALSE;
	return ContinueSuccess;
}

VOID
NTAPI
KdpReportLoadSymbolsStateChange(IN PSTRING PathName,
	IN  PKD_SYMBOLS_INFO SymbolInfo,
	IN BOOLEAN Unload,
	IN OUT PCONTEXT Context, DEBUG_CPU_CONTEXT* CpuContext, BOOLEAN sendonce)
{
	PSTRING ExtraData;
	STRING Data, Header;
	DBGKD_ANY_WAIT_STATE_CHANGE WaitStateChange = { 0 };
	ULONG PathNameLength;
	KCONTINUE_STATUS Status;

	/* Start wait loop */
	do
	{
		/* Build the architecture common parts of the message */
		KdpSetCommonState(DbgKdLoadSymbolsStateChange,
			Context,
			&WaitStateChange);

		/* Now finish creating the structure */
		KdpSetContextState(&WaitStateChange, Context);

		/* Fill out load data */
		WaitStateChange.u.LoadSymbols.UnloadSymbols = Unload;
		WaitStateChange.u.LoadSymbols.BaseOfDll = (ULONG64)(LONG_PTR)SymbolInfo->BaseOfDll;
		WaitStateChange.u.LoadSymbols.ProcessId = SymbolInfo->ProcessId;
		WaitStateChange.u.LoadSymbols.CheckSum = SymbolInfo->CheckSum;
		WaitStateChange.u.LoadSymbols.SizeOfImage = SymbolInfo->SizeOfImage;
		KdpZeroMemory((void*)KdpPathBuffer, KDP_MSG_BUFFER_SIZE);
		/* Check if we have a path name */
		if (PathName)
		{

			/*/* Copy it to the path buffer #1#
			KdpCopyMemoryChunks((ULONG_PTR)PathName->Buffer,
				KdpPathBuffer,
				PathName->Length,
				0,
				MMDBG_COPY_UNSAFE,
				&PathNameLength);*/

			KdpMoveMemory((void*)KdpPathBuffer, (void*)PathName->Buffer, PathName->Length);
			PathNameLength = PathName->Length;
			/* Null terminate */
			KdpPathBuffer[PathName->Length] = ANSI_NULL;

			/* Set the path length */
			WaitStateChange.u.LoadSymbols.PathNameLength = PathName->Length;

			/* Set up the data */
			Data.Buffer = KdpPathBuffer;
			Data.Length = (USHORT)PathName->Length;
			ExtraData = &Data;
		}
		else
		{
			/* No name */
			WaitStateChange.u.LoadSymbols.PathNameLength = 0;
			ExtraData = NULL;
		}

		/* Setup the header */
		Header.Length = sizeof(DBGKD_ANY_WAIT_STATE_CHANGE);
		Header.Buffer = (PCHAR)&WaitStateChange;
		if (sendonce)
		{

			KdSendPacket(PACKET_TYPE_KD_STATE_CHANGE64, &Header, ExtraData, &KdpContext);

			return;
		}
		else {
			/* Send the packet */
			Status = KdpSendWaitContinue(PACKET_TYPE_KD_STATE_CHANGE64,
				&Header,
				ExtraData,
				Context, CpuContext);
			if (ForceConsoleOutput)
			{
				KdpDprintf(L"after KdpReportLoadSymbolsStateChange\r\n");
			}
			//return;
		}
	} while (Status == ContinueProcessorReselected);

	return;
}

VOID
NTAPI
KdpReportCommandStringStateChange(IN PSTRING NameString,
	IN PSTRING CommandString,
	IN OUT PCONTEXT Context, DEBUG_CPU_CONTEXT* CpuContext)
{
	STRING Header, Data;
	DBGKD_ANY_WAIT_STATE_CHANGE WaitStateChange;
	ULONG Length, ActualLength, TotalLength;
	KCONTINUE_STATUS Status;

	/* Start wait loop */
	do
	{
		/* Build the architecture common parts of the message */
		KdpSetCommonState(DbgKdCommandStringStateChange,
			Context,
			&WaitStateChange);

		/* Set the context */
		KdpSetContextState(&WaitStateChange, Context);

		/* Clear the command string structure */
		KdpZeroMemory(&WaitStateChange.u.CommandString,
			sizeof(DBGKD_COMMAND_STRING));

		/* Normalize name string to max */
		Length = min(128 - 1, NameString->Length);

		/* Copy it to the message buffer */
		KdpCopyMemoryChunks((ULONG_PTR)NameString->Buffer,
			KdpMessageBuffer,
			Length,
			0,
			MMDBG_COPY_UNSAFE,
			&ActualLength);

		/* Null terminate and calculate the total length */
		TotalLength = ActualLength;
		KdpMessageBuffer[TotalLength++] = ANSI_NULL;

		/* Check if the command string is too long */
		Length = CommandString->Length;
		if (Length > (PACKET_MAX_SIZE -
			sizeof(DBGKD_ANY_WAIT_STATE_CHANGE) - TotalLength))
		{
			/* Use maximum possible size */
			Length = (PACKET_MAX_SIZE -
				sizeof(DBGKD_ANY_WAIT_STATE_CHANGE) - TotalLength);
		}

		/* Copy it to the message buffer */
		KdpCopyMemoryChunks((ULONG_PTR)CommandString->Buffer,
			KdpMessageBuffer + TotalLength,
			Length,
			0,
			MMDBG_COPY_UNSAFE,
			&ActualLength);

		/* Null terminate and calculate the total length */
		TotalLength += ActualLength;
		KdpMessageBuffer[TotalLength++] = ANSI_NULL;

		/* Now set up the header and the data */
		Header.Length = sizeof(DBGKD_ANY_WAIT_STATE_CHANGE);
		Header.Buffer = (PCHAR)&WaitStateChange;
		Data.Length = (USHORT)TotalLength;
		Data.Buffer = KdpMessageBuffer;

		/* Send State Change packet and wait for a reply */
		Status = KdpSendWaitContinue(PACKET_TYPE_KD_STATE_CHANGE64,
			&Header,
			&Data,
			Context, CpuContext);
	} while (Status == ContinueProcessorReselected);
}

BOOLEAN
NTAPI
KdpReportExceptionStateChange(IN PEXCEPTION_RECORD ExceptionRecord,
	IN OUT PCONTEXT Context,
	IN BOOLEAN SecondChanceException, DEBUG_CPU_CONTEXT* CpuContext)
{
	STRING Header, Data;
	DBGKD_ANY_WAIT_STATE_CHANGE WaitStateChange;
	KCONTINUE_STATUS Status;

	/* Start report loop */
	do
	{
		/* Build the architecture common parts of the message */
		KdpSetCommonState(DbgKdExceptionStateChange, Context, &WaitStateChange);



		/* Just copy it directly, no need to convert */
		KdpMoveMemory(&WaitStateChange.u.Exception.ExceptionRecord,
			ExceptionRecord,
			sizeof(EXCEPTION_RECORD));



		/* Set the First Chance flag */
		WaitStateChange.u.Exception.FirstChance = !SecondChanceException;

		/* Now finish creating the structure */
		KdpSetContextState(&WaitStateChange, Context);

		/* Setup the actual header to send to KD */

		Header.Buffer = (PCHAR)&WaitStateChange;
		Header.Length = sizeof(DBGKD_ANY_WAIT_STATE_CHANGE);

		Data.Length = Data.MaximumLength = 0;
		Data.Buffer = 0;
		/* Setup the trace data */
		//DumpTraceData(&Data);

		/* Send State Change packet and wait for a reply */
		Status = KdpSendWaitContinue(PACKET_TYPE_KD_STATE_CHANGE64,
			&Header,
			NULL,
			Context, CpuContext);
	} while (Status == ContinueProcessorReselected);

	/* Return */
	return 0;
}


/*
BOOLEAN
NTAPI
KdpReportTimerStateChange(IN PEXCEPTION_RECORD ExceptionRecord,
	IN OUT PCONTEXT Context,
	IN BOOLEAN SecondChanceException, DEBUG_CPU_CONTEXT* CpuContext)
{
	if (KdpContextSyncPacket == TRUE)
	{
		return 0;
	}
	STRING Header, Data;
	DBGKD_ANY_WAIT_STATE_CHANGE WaitStateChange;
	KCONTINUE_STATUS Status;

	/* Start report loop #1#
	do
	{
		/* Setup the actual header to send to KD #1#

		Header.Buffer = (PCHAR)&WaitStateChange;
		Header.Length = sizeof(DBGKD_ANY_WAIT_STATE_CHANGE);

		Data.Length = Data.MaximumLength = 0;
		Data.Buffer = 0;
		/* Setup the trace data #1#
		//DumpTraceData(&Data);

		/* Send State Change packet and wait for a reply #1#
		Status = KdpReceiveWaitContinue(PACKET_TYPE_KD_STATE_CHANGE64,
			&Header,
			NULL,
			Context, CpuContext);
	} while (Status == ContinueProcessorReselected);

	/* Return #1#
	return 0;
}
*/


BOOLEAN
NTAPI
KdpSwitchProcessor(IN PEXCEPTION_RECORD ExceptionRecord,
	IN OUT PCONTEXT ContextRecord,
	IN BOOLEAN SecondChanceException)
{
	BOOLEAN Status;

	/* Save the port data */
	KdSave(FALSE);

	/* Report a state change */
	Status = KdpReportExceptionStateChange(ExceptionRecord,
		ContextRecord,
		SecondChanceException, NULL);

	/* Restore the port data and return */
	KdRestore(FALSE);
	return Status;
}

LARGE_INTEGER
NTAPI
KdpQueryPerformanceCounter(IN PKTRAP_FRAME TrapFrame)
{
	LARGE_INTEGER retval = { {0} };

	/* Check if interrupts were disabled */
	if (!KeGetTrapFrameInterruptState(TrapFrame))
	{
		/* Nothing to return */
		return retval;
	}
	retval.QuadPart = KeQueryPerformanceCounter(NULL);
	/* Otherwise, do the call */
	return retval;
}
NTSTATUS
NTAPI
KeThawExecution(
	IN BOOLEAN SleepTransition
)
{
	return 0;
}
NTSTATUS
NTAPI
KdRestore(
	IN BOOLEAN SleepTransition
)
{
	return 0;
}

NTSTATUS
NTAPI
KdSave(
	IN BOOLEAN SleepTransition
) {
	return 0;
}

BOOLEAN
NTAPI
KdEnterDebugger(IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame)
{
	BOOLEAN Enable = TRUE;

	/* Check if we have a trap frame */
	if (TrapFrame)
	{
		/* Calculate the time difference for the enter */
		KdTimerStop = KdpQueryPerformanceCounter(TrapFrame);
		KdTimerDifference.QuadPart = KdTimerStop.QuadPart -
			KdTimerStart.QuadPart;
	}
	else
	{
		/* No trap frame, so can't calculate */
		KdTimerStop.QuadPart = 0;
	}


	/* Freeze all CPUs, raising also the IRQL to HIGH_LEVEL */
   // Enable = KeFreezeExecution(TrapFrame, ExceptionFrame);

	/* Lock the port, save the state and set debugger entered */
  //  KdpPortLocked = KeTryToAcquireSpinLockAtDpcLevel(&KdpDebuggerLock);
	KdSave(FALSE);
	KdEnteredDebugger = TRUE;

	/*
	/* Check freeze flag #1#
	if (KiFreezeFlag & 1)
	{
		/* Print out errror #1#
		KdpDprintf(L"FreezeLock was jammed!  Backup SpinLock was used!\n");
	}

	/* Check processor state #1#
	if (KiFreezeFlag & 2)
	{
		/* Print out errror #1#
		KdpDprintf(L"Some processors not frozen in debugger!\n");
	}
	*/

	/* Make sure we acquired the port
	 * Return if interrupts needs to be re-enabled */
	 //if (!KdpPortLocked) KdpDprintf(L"Port lock was not acquired!\n");
	return Enable;
}

VOID
NTAPI
KdExitDebugger(IN BOOLEAN Enable)
{
	ULONG TimeSlip;

	/* Restore the state and unlock the port */
	KdRestore(FALSE);
	if (KdpPortLocked) KdpPortUnlock();

	/* Unfreeze the CPUs, restoring also the IRQL */
	KeThawExecution(Enable);

	/* Compare time with the one from KdEnterDebugger */
	if (!KdTimerStop.QuadPart)
	{
		/* We didn't get a trap frame earlier in so never got the time */
		KdTimerStart = KdTimerStop;
	}
	else
	{
		/* Query the timer */
		KdTimerStart.QuadPart = KeQueryPerformanceCounter(NULL);
	}

	/* Check if a Time Slip was on queue */
	TimeSlip = InterlockedIncrement(&KdpTimeSlipPending);
	if (TimeSlip == 1)
	{
		/* Queue a DPC for the time slip */
		InterlockedIncrement(&KdpTimeSlipPending);
		//KeInsertQueueDpc(&KdpTimeSlipDpc, NULL, NULL); // FIXME: this can trigger context switches!
	}
	return;
}

NTSTATUS
NTAPI
KdEnableDebuggerWithLock(IN BOOLEAN NeedLock)
{
	KIRQL OldIrql;


	/* Make gcc happy */
	OldIrql = PASSIVE_LEVEL;


	/* Check if enabling the debugger is blocked */
	if (KdBlockEnable)
	{
		/* It is, fail the enable */
		return STATUS_ACCESS_DENIED;
	}

	/* Check if we need to acquire the lock */
	if (NeedLock)
	{
		/* Lock the port */
		KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
		KdpPortLock();
	}

	/* Check if we're not disabled */
	if (!KdDisableCount)
	{
		/* Check if we had locked the port before */
		if (NeedLock)
		{
			/* Do the unlock */
			KdpPortUnlock();
			KeLowerIrql(OldIrql);

			/* Fail: We're already enabled */
			return STATUS_INVALID_PARAMETER;
		}
		else
		{
			/*
			 * This can only happen if we are called from a bugcheck
			 * and were never initialized, so initialize the debugger now.
			 */
			 // KdInitSystem(0, NULL);

			  /* Return success since we initialized */
			return STATUS_SUCCESS;
		}
	}

	/* Decrease the disable count */
	if (!(--KdDisableCount))
	{
		/* We're now enabled again! Were we enabled before, too? */
		if (KdPreviouslyEnabled)
		{
			/* Reinitialize the Debugger */
			//KdInitSystem(0, NULL);
			KdpRestoreAllBreakpoints();
		}
	}

	/* Check if we had locked the port before */
	if (NeedLock)
	{
		/* Yes, now unlock it */
		KdpPortUnlock();
		KeLowerIrql(OldIrql);
	}

	/* We're done */
	return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdDisableDebuggerWithLock(IN BOOLEAN NeedLock)
{
	KIRQL OldIrql;
	NTSTATUS Status;

#if defined(__GNUC__)
	/* Make gcc happy */
	OldIrql = PASSIVE_LEVEL;
#endif

	/*
	 * If enabling the debugger is blocked
	 * then there is nothing to disable (duh)
	 */
	if (KdBlockEnable)
	{
		/* Fail */
		return STATUS_ACCESS_DENIED;
	}

	/* Check if we need to acquire the lock */
	if (NeedLock)
	{
		/* Lock the port */
		KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
		KdpPortLock();
	}

	/* Check if we're not disabled */
	if (!KdDisableCount)
	{
		/* Check if the debugger was never actually initialized */
		if (!(KdDebuggerEnabled) && !(KdPitchDebugger))
		{
			/* It wasn't, so don't re-enable it later */
			KdPreviouslyEnabled = FALSE;
		}
		else
		{
			/* It was, so we will re-enable it later */
			KdPreviouslyEnabled = TRUE;
		}

		/* Check if we were called from the exported API and are enabled */
		if ((NeedLock) && (KdPreviouslyEnabled))
		{
			/* Check if it is safe to disable the debugger */
			Status = KdpAllowDisable();
			if (!NT_SUCCESS(Status))
			{
				/* Release the lock and fail */
				KdpPortUnlock();
				KeLowerIrql(OldIrql);
				return Status;
			}
		}

		/* Only disable the debugger if it is enabled */
		if (KdDebuggerEnabled)
		{
			/*
			 * Disable the debugger; suspend breakpoints
			 * and reset the debug stub
			 */
			KdpSuspendAllBreakPoints();
			//KiDebugRoutine = KdpStub;

			/* We are disabled now */
			KdDebuggerEnabled = FALSE;
			//SharedUserData->KdDebuggerEnabled = FALSE;
		}
	}

	/* Increment the disable count */
	KdDisableCount++;

	/* Check if we had locked the port before */
	if (NeedLock)
	{
		/* Yes, now unlock it */
		KdpPortUnlock();
		KeLowerIrql(OldIrql);
	}

	/* We're done */
	return STATUS_SUCCESS;
}

/* PUBLIC FUNCTIONS **********************************************************/

/*
 * @implemented
 */
NTSTATUS
NTAPI
KdEnableDebugger(VOID)
{
	/* Use the internal routine */
	return KdEnableDebuggerWithLock(TRUE);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
KdDisableDebugger(VOID)
{
	/* Use the internal routine */
	return KdDisableDebuggerWithLock(TRUE);
}


BOOLEAN
NTAPI
KdRefreshDebuggerNotPresent(VOID)
{
	BOOLEAN Enable, DebuggerNotPresent;

	/* Check if the debugger is completely disabled */
	if (KdPitchDebugger)
	{
		/* Don't try to refresh then, fail early */
		return TRUE;
	}

	/* Enter the debugger */
	Enable = KdEnterDebugger(NULL, NULL);

	/*
	 * Attempt to send a string to the debugger
	 * to refresh the connection state.
	 */
	KdpDprintf(L"KDTARGET: Refreshing KD connection\n");

	/* Save the state while we are holding the lock */
	DebuggerNotPresent = KdDebuggerNotPresent;

	/* Exit the debugger and return the state */
	KdExitDebugger(Enable);
	return DebuggerNotPresent;
}



VOID
NTAPI
KdLogDbgPrint(
	_In_ PSTRING String)
{
	UINT32 Length, Remaining;
	//	KIRQL OldIrql;

		/* If the string is empty, bail out */
	if (!String->Buffer || (String->Length == 0))
		return;

	/* If no log buffer available, bail out */
	if (!KdPrintCircularBuffer /*|| (KdPrintBufferSize == 0)*/)
		return;

	/* Acquire the log spinlock without waiting at raised IRQL */
  //  OldIrql = KdpAcquireLock(&KdpPrintSpinLock);
	AcquireMpSpinLock(&mDebugMpContext.MpContextSpinLock);
	Length = min(String->Length, KdPrintBufferSize);
	Remaining = (UINT32)(KdPrintCircularBuffer + KdPrintBufferSize - KdPrintWritePointer);

	if (Length < Remaining)
	{
		KdpMoveMemory(KdPrintWritePointer, String->Buffer, Length);
		KdPrintWritePointer += Length;
	}
	else
	{
		KdpMoveMemory(KdPrintWritePointer, String->Buffer, Remaining);
		Length -= Remaining;
		if (Length > 0)
			KdpMoveMemory(KdPrintCircularBuffer, String->Buffer + Remaining, Length);

		KdPrintWritePointer = KdPrintCircularBuffer + Length;

		/* Got a rollover, update count (handle wrapping, must always be >= 1) */
		++KdPrintRolloverCount;
		if (KdPrintRolloverCount == 0)
			++KdPrintRolloverCount;
	}

	/* Release the spinlock */
   // KdpReleaseLock(&KdpPrintSpinLock, OldIrql);
	ReleaseMpSpinLock(&mDebugMpContext.MpContextSpinLock);
}

BOOLEAN
NTAPI
KdpPrintString(
	_In_ PSTRING Output)
{
	STRING Data, Header;
	DBGKD_DEBUG_IO DebugIo;
	USHORT Length = Output->Length;

	/* Copy the string */
	KdpMoveMemory(KdpPathAuxBuffer,
		Output->Buffer,
		Output->Length);
	KdpPathAuxBuffer[Output->Length] = '\0';
	KdpPathAuxBuffer[Output->Length + 1] = '\0';
	KdpPathAuxBuffer[Output->Length + 2] = '\0';
	KdpPathAuxBuffer[Output->Length + 3] = '\0';
	UINT64 lenchk = AsciiStrSize(KdpPathAuxBuffer);
	if (lenchk == 0)
	{
		return TRUE;
	}
	/* Make sure we don't exceed the KD Packet size */

	if ((sizeof(DBGKD_DEBUG_IO) + Length) > PACKET_MAX_SIZE)
	{
		/* Normalize length */
		Length = PACKET_MAX_SIZE - sizeof(DBGKD_DEBUG_IO);
	}

	/* Build the packet header */
	DebugIo.ApiNumber = DbgKdPrintStringApi;
	DebugIo.ProcessorLevel = (USHORT)KdpNowKIRQL;
	DebugIo.Processor = (USHORT)GetProcessorIndex();
	DebugIo.u.PrintString.LengthOfString = Length;
	Header.Length = sizeof(DBGKD_DEBUG_IO);
	Header.Buffer = (PCHAR)&DebugIo;

	/* Build the data */
	Data.Length = Length;
	Data.Buffer = KdpPathAuxBuffer;
	KdpContext.KdpControlReturn = TRUE;
	/* Send the packet 这个是会回包的*/
	//KdSendPacketWithoutAcknowledge(PACKET_TYPE_KD_DEBUG_IO, &Header, &Data, &KdpContext);
	KdSendPacket(PACKET_TYPE_KD_DEBUG_IO, &Header, &Data, &KdpContext);

	/* Check if the user pressed CTRL+C */
	//return KdpPollBreakInWithPortLock();
	return TRUE;
}

BOOLEAN
NTAPI
KdpPromptString(
	_In_ PSTRING PromptString,
	_In_ PSTRING ResponseString)
{
	STRING Data, Header;
	DBGKD_DEBUG_IO DebugIo;
	ULONG Length;
	KDSTATUS Status;

	/* Copy the string to the message buffer */
	KdpMoveMemory(KdpMessageBuffer,
		PromptString->Buffer,
		PromptString->Length);

	/* Make sure we don't exceed the KD Packet size */
	Length = PromptString->Length;
	if ((sizeof(DBGKD_DEBUG_IO) + Length) > PACKET_MAX_SIZE)
	{
		/* Normalize length */
		Length = PACKET_MAX_SIZE - sizeof(DBGKD_DEBUG_IO);
	}

	/* Build the packet header */
	DebugIo.ApiNumber = DbgKdGetStringApi;
	DebugIo.ProcessorLevel = (USHORT)KdpNowKIRQL;
	DebugIo.Processor = (USHORT)GetProcessorIndex();
	DebugIo.u.GetString.LengthOfPromptString = Length;
	DebugIo.u.GetString.LengthOfStringRead = ResponseString->MaximumLength;
	Header.Length = sizeof(DBGKD_DEBUG_IO);
	Header.Buffer = (PCHAR)&DebugIo;

	/* Build the data */
	Data.Length = (USHORT)Length;
	Data.Buffer = KdpMessageBuffer;

	/* Send the packet */
	KdSendPacket(PACKET_TYPE_KD_DEBUG_IO, &Header, &Data, &KdpContext);

	/* Set the maximum lengths for the receive */
	Header.MaximumLength = sizeof(DBGKD_DEBUG_IO);
	Data.MaximumLength = sizeof(KdpMessageBuffer);

	/* Enter receive loop */
	do
	{
		/* Get our reply */
		Status = KdReceivePacket(PACKET_TYPE_KD_DEBUG_IO,
			&Header,
			&Data,
			&Length,
			&KdpContext);

		/* Return TRUE if we need to resend */
		if (Status == KdPacketNeedsResend) return TRUE;

		/* Loop until we succeed */
	} while (Status != KdPacketReceived);

	/* Don't copy back a larger response than there is room for */
	Length = min(Length,
		ResponseString->MaximumLength);

	/* Copy back the string and return the length */
	KdpMoveMemory(ResponseString->Buffer,
		KdpMessageBuffer,
		Length);
	ResponseString->Length = (USHORT)Length;

	/* Success; we don't need to resend */
	return FALSE;
}

VOID
NTAPI
KdpCommandString(IN PSTRING NameString,
	IN PSTRING CommandString,
	IN KPROCESSOR_MODE PreviousMode,
	IN PCONTEXT ContextRecord,
	IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame, DEBUG_CPU_CONTEXT* CpuContext)
{
	BOOLEAN Enable;
	//UINT64 ContextFrame = 0;
	/* Enter the debugger */
	Enable = KdEnterDebugger(TrapFrame, ExceptionFrame);

	/* Save the CPU Control State and save the context */
   // KiSaveProcessorControlState(&Prcb->ProcessorState);
	/*KdpMoveMemory(&Prcb->ProcessorState.ContextFrame,
		ContextRecord,
		sizeof(CONTEXT));*/

		/* Send the command string to the debugger */
	KdpReportCommandStringStateChange(NameString,
		CommandString,
		ContextRecord, CpuContext);

	/* Restore the processor state */
	/*KdpMoveMemory(ContextRecord,
		&Prcb->ProcessorState.ContextFrame,
		sizeof(CONTEXT));*/
		//  KiRestoreProcessorControlState(&Prcb->ProcessorState);

		  /* Exit the debugger and return */
	KdExitDebugger(Enable);
}

VOID
NTAPI
KdpSymbol(IN PSTRING DllPath,
	IN PKD_SYMBOLS_INFO SymbolInfo,
	IN BOOLEAN Unload,
	IN KPROCESSOR_MODE PreviousMode,
	IN PCONTEXT ContextRecord,
	IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame, DEBUG_CPU_CONTEXT* CpuContext, BOOLEAN sendonce)
{
	BOOLEAN Enable;
	CONTEXT ContextFrame = { 0 };
	/* Enter the debugger */
	Enable = KdEnterDebugger(TrapFrame, ExceptionFrame);

	/* Save the CPU Control State and save the context */
	//KiSaveProcessorControlState(&Prcb->ProcessorState);
	/*KdpMoveMemory(&Prcb->ProcessorState.ContextFrame,
		ContextRecord,
		sizeof(CONTEXT));*/
	if (ContextRecord)
	{
		KdpMoveMemory(&ContextFrame,
			ContextRecord,
			sizeof(CONTEXT));
	}
	/* Report the new state */
	KdpReportLoadSymbolsStateChange(DllPath,
		SymbolInfo,
		Unload,
		&ContextFrame, CpuContext, sendonce);

	/* Restore the processor state */
	/*KdpMoveMemory(ContextRecord,
		&Prcb->ProcessorState.ContextFrame,
		sizeof(CONTEXT));*/
	if (ContextRecord)
	{
		/* Restore the processor state */
		KdpMoveMemory(ContextRecord,
			&ContextFrame,
			sizeof(CONTEXT));
	}
	//KiRestoreProcessorControlState(&Prcb->ProcessorState);

	/* Exit the debugger and return */
	KdExitDebugger(Enable);

	return;
}

USHORT
NTAPI
KdpPrompt(
	_In_reads_bytes_(PromptLength) PCHAR PromptString,
	_In_ USHORT PromptLength,
	_Out_writes_bytes_(MaximumResponseLength) PCHAR ResponseString,
	_In_ USHORT MaximumResponseLength,
	_In_ KPROCESSOR_MODE PreviousMode,
	_In_ PKTRAP_FRAME TrapFrame,
	_In_ PKEXCEPTION_FRAME ExceptionFrame)
{
	STRING PromptBuffer, ResponseBuffer;
	BOOLEAN Enable, Resend;
	PCHAR SafeResponseString;
	CHAR CapturedPrompt[KD_PRINT_MAX_BYTES];
	CHAR SafeResponseBuffer[KD_PRINT_MAX_BYTES];

	/* Normalize the lengths */
	PromptLength = min(PromptLength,
		sizeof(CapturedPrompt));
	MaximumResponseLength = min(MaximumResponseLength,
		sizeof(SafeResponseBuffer));

	SafeResponseString = ResponseString;


	/* Setup the prompt and response buffers */
	PromptBuffer.Buffer = PromptString;
	PromptBuffer.Length = PromptBuffer.MaximumLength = PromptLength;
	ResponseBuffer.Buffer = SafeResponseString;
	ResponseBuffer.Length = 0;
	ResponseBuffer.MaximumLength = MaximumResponseLength;

	/* Log the print */
	KdLogDbgPrint(&PromptBuffer);

	/* Enter the debugger */
	Enable = KdEnterDebugger(TrapFrame, ExceptionFrame);

	/* Enter prompt loop */
	do
	{
		/* Send the prompt and receive the response */
		Resend = KdpPromptString(&PromptBuffer, &ResponseBuffer);

		/* Loop while we need to resend */
	} while (Resend);

	/* Exit the debugger */
	KdExitDebugger(Enable);

	/* Copy back the response if required */

			/* Safely copy back the response to user mode */
	KdpMoveMemory(ResponseString,
		ResponseBuffer.Buffer,
		ResponseBuffer.Length);



	/* Return the number of characters received */
	return ResponseBuffer.Length;
}

static
NTSTATUS
NTAPI
KdpPrintFromUser(
	_In_ ULONG ComponentId,
	_In_ ULONG Level,
	_In_reads_bytes_(Length) PCHAR String,
	_In_ USHORT Length,
	_In_ KPROCESSOR_MODE PreviousMode,
	_In_ PKTRAP_FRAME TrapFrame,
	_In_ PKEXCEPTION_FRAME ExceptionFrame,
	_Out_ PBOOLEAN Handled)
{
	CHAR CapturedString[KD_PRINT_MAX_BYTES];

	/*
	ASSERT(PreviousMode == UserMode);
	ASSERT(Length <= sizeof(CapturedString));
	*/

	/* Capture user-mode buffers */

		/* Probe and capture the string */
	//ProbeForRead(String, Length, 1);
	KdpMoveMemory(CapturedString, String, Length);
	String = CapturedString;


	/* Now go through the kernel-mode code path */
	return KdpPrint(ComponentId,
		Level,
		String,
		Length,
		0,
		TrapFrame,
		ExceptionFrame,
		Handled);
}

NTSTATUS
NTAPI
KdpPrint(
	_In_ ULONG ComponentId,
	_In_ ULONG Level,
	_In_reads_bytes_(Length) PCHAR String,
	_In_ USHORT Length,
	_In_ KPROCESSOR_MODE PreviousMode,
	_In_ PKTRAP_FRAME TrapFrame,
	_In_ PKEXCEPTION_FRAME ExceptionFrame,
	_Out_ PBOOLEAN Handled)
{
	NTSTATUS Status;
	BOOLEAN Enable;
	STRING OutputString;


	/* Assume failure */
	*Handled = FALSE;

	/* Normalize the length */
	Length = min(Length, KD_PRINT_MAX_BYTES);

	/*/* Check if we need to verify the string #1#
	if (PreviousMode != KernelMode)
	{
		/* This case requires a 512 byte stack buffer.
		 * We don't want to use that much stack in the kernel case, but we
		 * can't use _alloca due to PSEH. So the buffer exists in this
		 * helper function instead.
		 #1#
		return KdpPrintFromUser(ComponentId,
			Level,
			String,
			Length,
			PreviousMode,
			TrapFrame,
			ExceptionFrame,
			Handled);
	}*/

	/* Setup the output string */
	OutputString.Buffer = String;
	OutputString.Length = OutputString.MaximumLength = Length;

	/* Log the print */
	KdLogDbgPrint(&OutputString);

	/* Check for a debugger */
	if (KdDebuggerNotPresent)
	{
		/* Fail */
		*Handled = TRUE;
		return STATUS_DEVICE_NOT_CONNECTED;
	}

	/* Enter the debugger */
	Enable = KdEnterDebugger(TrapFrame, ExceptionFrame);

	/* Print the string */
	if (KdpPrintString(&OutputString))
	{
		/* User pressed CTRL-C, breakpoint on return */
		Status = STATUS_BREAKPOINT;
	}
	else
	{
		/* String was printed */
		Status = STATUS_SUCCESS;
	}

	/* Exit the debugger and return */
	KdExitDebugger(Enable);
	*Handled = TRUE;
	return Status;
}

EFI_STATUS EFIAPI OutputMsgFromClient(CHAR16* msg)
{
	KdpDprintf(msg);
	return STATUS_SUCCESS;
}

void EFIAPI FixGdtrMap()
{

	ULONG            GdtBufferSize;
	IA32_DESCRIPTOR  Gdtr;

	UINT64 GdtBuffer;
	AsmReadGdtr((IA32_DESCRIPTOR*)&Gdtr);
	GdtBufferSize = sizeof(IA32_SEGMENT_DESCRIPTOR) - 1 + Gdtr.Limit + 1;
	GdtBuffer = (UINT64)AllocateZeroPool(0x1000);
	KdpMoveMemory((VOID*)GdtBuffer, (VOID*)Gdtr.Base, Gdtr.Limit + 1);
	gsymmap[0].BaseOfAddr = Gdtr.Base;
	gsymmap[0].MapOfAddr = GdtBuffer;
	gsymmap[0].SizeOfAddr = 0x1000;
	if (ForceConsoleOutput)
	{
		KdpDprintf(L"FixGdtrMap BaseOfDll %p MapOfDll %p Length %08x ok\r\n", gsymmap[0].BaseOfAddr, gsymmap[0].MapOfAddr, gsymmap[0].SizeOfAddr);
		dumpbuf((VOID*)Gdtr.Base, (int)(Gdtr.Limit & 0xf0));

	}
	return;

}
NTSTATUS hdlmsgint();

/**
  Initialize IDT entries to support source level debug.

**/
VOID NTAPI
InitializeDebugIdtWindbg(
	VOID
)
{
	IA32_IDT_GATE_DESCRIPTOR* IdtEntry;
	UINTN                     InterruptHandler;
	IA32_DESCRIPTOR           IdtDescriptor;
	UINTN                     Index;
	UINT16                    CodeSegment;
	UINT32                    RegEdx;

	AsmReadIdtr(&IdtDescriptor);

	//
	// Use current CS as the segment selector of interrupt gate in IDT
	//
	CodeSegment = AsmReadCs();

	IdtEntry = (IA32_IDT_GATE_DESCRIPTOR*)IdtDescriptor.Base;

	for (Index = 0; Index < 20; Index++) {


		InterruptHandler = (UINTN)&Exception0Handle + Index * ExceptionStubHeaderSize;
		IdtEntry[Index].Bits.OffsetLow = (UINT16)(UINTN)InterruptHandler;
		IdtEntry[Index].Bits.OffsetHigh = (UINT16)((UINTN)InterruptHandler >> 16);
		IdtEntry[Index].Bits.Selector = CodeSegment;
		IdtEntry[Index].Bits.GateType = IA32_IDT_GATE_TYPE_INTERRUPT_32;
	}

	InterruptHandler = (UINTN)&TimerInterruptHandle;
	IdtEntry[DEBUG_TIMER_VECTOR].Bits.OffsetLow = (UINT16)(UINTN)InterruptHandler;
	IdtEntry[DEBUG_TIMER_VECTOR].Bits.OffsetHigh = (UINT16)((UINTN)InterruptHandler >> 16);
	IdtEntry[DEBUG_TIMER_VECTOR].Bits.Selector = CodeSegment;
	IdtEntry[DEBUG_TIMER_VECTOR].Bits.GateType = IA32_IDT_GATE_TYPE_INTERRUPT_32;



	InterruptHandler = (UINTN)&hdlmsgint;
	IdtEntry[HYPERVISOR_CALLBACK_VECTOR].Bits.OffsetLow = (UINT16)(UINTN)InterruptHandler;
	IdtEntry[HYPERVISOR_CALLBACK_VECTOR].Bits.OffsetHigh = (UINT16)((UINTN)InterruptHandler >> 16);
	IdtEntry[HYPERVISOR_CALLBACK_VECTOR].Bits.Selector = CodeSegment;
	IdtEntry[HYPERVISOR_CALLBACK_VECTOR].Bits.GateType = IA32_IDT_GATE_TYPE_INTERRUPT_32;

	//
	// If the CPU supports Debug Extensions(CPUID:01 EDX:BIT2), then
	// Set DE flag in CR4 to enable IO breakpoint
	//
	AsmCpuid(1, NULL, NULL, NULL, &RegEdx);
	if ((RegEdx & BIT2) != 0) {
		AsmWriteCr4(AsmReadCr4() | BIT3);
	}
	return;
}
NTSTATUS NTAPI HvSYNICVtl0();

/**
  Worker function to set up Debug Agent environment.

  This function will set up IDT table and initialize the IDT entries and
  initialize CPU LOCAL APIC timer.
  It also tries to connect HOST if Debug Agent was not initialized before.

  @param[in] Mailbox        Pointer to Mailbox.

**/
VOID NTAPI
SetupDebugAgentEnvironmentWindbg(IN EFI_HANDLE        ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable,
	IN DEBUG_AGENT_MAILBOX* Mailbox
)
{
	IA32_DESCRIPTOR  Idtr;
	UINT16           IdtEntryCount;
	UINT64           DebugPortHandle;
	UINT32           DebugTimerFrequency;

	if (mMultiProcessorDebugSupport) {
		InitializeSpinLock(&mDebugMpContext.MpContextSpinLock);
		InitializeSpinLock(&mDebugMpContext.DebugPortSpinLock);
		InitializeSpinLock(&mDebugMpContext.MailboxSpinLock);
		//
		// Clear Break CPU index value
		//
		mDebugMpContext.BreakAtCpuIndex = (UINT32)-1;
	}

	//
	// Get original IDT address and size.
	//
	AsmReadIdtr((IA32_DESCRIPTOR*)&Idtr);
	IdtEntryCount = (UINT16)((Idtr.Limit + 1) / sizeof(IA32_IDT_GATE_DESCRIPTOR));
	if (IdtEntryCount < 33) {
		KdpZeroMemory(&mIdtEntryTable, sizeof(IA32_IDT_GATE_DESCRIPTOR) * 33);
		//
		// Copy original IDT table into new one
		//
		KdpMoveMemory(&mIdtEntryTable, (VOID*)Idtr.Base, Idtr.Limit + 1);
		//
		// Load new IDT table
		//
		Idtr.Limit = (UINT16)(sizeof(IA32_IDT_GATE_DESCRIPTOR) * 33 - 1);
		Idtr.Base = (UINTN)&mIdtEntryTable;
		AsmWriteIdtr((IA32_DESCRIPTOR*)&Idtr);
	}

	//
	// Initialize the IDT table entries to support source level debug.
	//
	InitializeDebugIdtWindbg();
	HvSYNICVtl0();
	//
	// If mMailboxPointer is not set before, set it
	//
	if (mMailboxPointer == NULL) {
		if (Mailbox != NULL) {
			//
			// If Mailbox exists, copy it into one global variable
			//
			KdpMoveMemory(&mMailbox, Mailbox, sizeof(DEBUG_AGENT_MAILBOX));
		}
		else {
			KdpZeroMemory(&mMailbox, sizeof(DEBUG_AGENT_MAILBOX));
		}

		mMailboxPointer = &mMailbox;
	}




	//
	// Initialize Debug Timer hardware and save its initial count and frequency
	//
	mDebugMpContext.DebugTimerInitCount = InitializeDebugTimer(&DebugTimerFrequency, TRUE);
	UpdateMailboxContent(mMailboxPointer, DEBUG_MAILBOX_DEBUG_TIMER_FREQUENCY, DebugTimerFrequency);
	//
	// Initialize debug communication port
	//
	if (gVmbusWindbgProtocol == NativeCom)
	{
		DebugPortHandle = (UINT64)(UINTN)DebugPortInitialize((VOID*)(UINTN)mMailboxPointer->DebugPortHandle, NULL);
		UpdateMailboxContent(mMailboxPointer, DEBUG_MAILBOX_DEBUG_PORT_HANDLE_INDEX, DebugPortHandle);
	}
	//启用timer
	SaveAndSetDebugTimerInterrupt(TRUE);
	if (ForceConsoleOutput)
	{
		DEBUG((DEBUG_INFO, "SaveAndSetDebugTimerInterrupt\r\n"));
	}
	// Enable interrupt to receive Debug Timer interrupt
	//

	//
	if (gVmbusWindbgProtocol == VmbusChannel)
	{
		HvVmbusServiceDxeInitialize();
	}
	EnableInterrupts();

	if (ForceConsoleOutput)
	{
		DEBUG((DEBUG_INFO, "EnableInterrupts\r\n"));
	}

	KdInitSystem(ImageHandle, SystemTable, FALSE, NULL);


	if (Mailbox == NULL) {
		//
		// Trigger one software interrupt to inform HOST
		//
		TriggerSoftInterrupt(SYSTEM_RESET_SIGNATURE);
		SetDebugFlag(DEBUG_AGENT_FLAG_MEMORY_READY, 1);
		//
		// Memory has been ready
		//
		if (IsHostAttached()) {
			//
			// Trigger one software interrupt to inform HOST
			//
			TriggerSoftInterrupt(MEMORY_READY_SIGNATURE);
		}
	}

	//__debugbreak();

	/*Print(L"stall\r\n");
	while (TRUE)
	{
		stall(10);
	}*/
	return;
}



BOOLEAN EFIAPI KdInitSystem(IN EFI_HANDLE   ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable, ULONG BootPhase, void* LoaderBlock)
{



	FixGdtrMap();
	pPengdingManipulatePacket = (PKD_PACKETEXTRA)AllocateZeroPool(sizeof(KD_PACKETEXTRA));
	InitializeListHeadUefi(&pPengdingManipulatePacket->List);

	KdpZeroMemory(mSyntheticSymbolInfo, sizeof(mSyntheticSymbolInfo));
	PUEFI_SYMBOLS_INFO pSyntheticSymbolInfo = &mSyntheticSymbolInfo[0];
	KdpContext.KdpDefaultRetries = 20;
	KdpContext.KdpControlCPending = FALSE;
	KdpContext.KdpControlReturn = FALSE;
	if (ForceConsoleOutput)
	{
		DEBUG((DEBUG_INFO, "KdInitSystem\r\n"));


	}

	KdpSendControlPacket(PACKET_TYPE_KD_RESET, 0);
	

	//

	PEFI_WINDBGPROTOCOL myProtocol = &gWindbgProtocol;
	myProtocol->Revsion = 1;
	myProtocol->OutputMsg = OutputMsgFromClient;

	EFI_STATUS	Status = gBS->InstallProtocolInterface(
		&ImageHandle,
		&gEfiWindbgProtocolGUID,
		EFI_NATIVE_INTERFACE,
		&gWindbgProtocol
	);
	if (ForceConsoleOutput)
	{
		if (!EFI_ERROR(Status))
		{
			KdpDprintf(L"KdInitSystem Success\n");

		}
		else {
			KdpDprintf(L"KdInitSystem Failed\n");
		}
	}

	FindAndReportModuleImageInfoWindbg(SIZE_4KB, pSyntheticSymbolInfo);

	if (ReportSynthetic == 0)
	{

		KdpSymbolReportSynthetic();
		//CurrentPacketId ^= 1;
		KdpDprintf(L"KdInitSystem Success\n");
		VmbusKdInitSystemLoaded = TRUE;
		return TRUE;
	}



	return  TRUE;
};

BOOLEAN NTAPI KdExitSystem(IN EFI_HANDLE  ImageHandle)
{

	gBS->UninstallProtocolInterface(
		ImageHandle,
		&gEfiWindbgProtocolGUID,
		&gWindbgProtocol
	);

	return  TRUE;
}
KCONTINUE_STATUS
NTAPI
KdpSendWaitContinue(IN ULONG PacketType,
	IN PSTRING SendHeader,
	IN PSTRING SendData OPTIONAL,
	IN OUT PCONTEXT Context, DEBUG_CPU_CONTEXT* CpuContext);

GLOBAL_REMOVE_IF_UNREFERENCED CHAR8  mErrorMsgVersionAlert[] = "\rThe SourceLevelDebugPkg you are using requires a newer version of the Intel(R) UDK Debugger Tool.\r\n";
GLOBAL_REMOVE_IF_UNREFERENCED CHAR8  mErrorMsgSendInitPacket[] = "\rSend INIT break packet and try to connect the HOST (Intel(R) UDK Debugger Tool v1.5) ...\r\n";
GLOBAL_REMOVE_IF_UNREFERENCED CHAR8  mErrorMsgConnectOK[] = "HOST connection is successful!\r\n";
GLOBAL_REMOVE_IF_UNREFERENCED CHAR8  mErrorMsgConnectFail[] = "HOST connection is failed!\r\n";
GLOBAL_REMOVE_IF_UNREFERENCED CHAR8  mWarningMsgIngoreBreakpoint[] = "Ignore break point in SMM for SMI issued during DXE debugging!\r\n";

//
// Vector Handoff Info list used by Debug Agent for persist
//
GLOBAL_REMOVE_IF_UNREFERENCED EFI_VECTOR_HANDOFF_INFO  mVectorHandoffInfoDebugAgent[] = {
  {
	DEBUG_EXCEPT_DIVIDE_ERROR,         // Vector 0
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_DEBUG,                // Vector 1
	EFI_VECTOR_HANDOFF_DO_NOT_HOOK,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_NMI,                  // Vector 2
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_BREAKPOINT,           // Vector 3
	EFI_VECTOR_HANDOFF_DO_NOT_HOOK,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_OVERFLOW,             // Vector 4
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_BOUND,                // Vector 5
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_INVALID_OPCODE,       // Vector 6
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_DOUBLE_FAULT,         // Vector 8
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_INVALID_TSS,          // Vector 10
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_SEG_NOT_PRESENT,      // Vector 11
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_STACK_FAULT,          // Vector 12
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_GP_FAULT,             // Vector 13
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_PAGE_FAULT,           // Vector 14
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_FP_ERROR,             // Vector 16
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_ALIGNMENT_CHECK,      // Vector 17
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_MACHINE_CHECK,        // Vector 18
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_EXCEPT_SIMD,                 // Vector 19
	EFI_VECTOR_HANDOFF_HOOK_BEFORE,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_TIMER_VECTOR,                // Vector 32
	EFI_VECTOR_HANDOFF_DO_NOT_HOOK,
	EFI_DEBUG_AGENT_GUID
  },
  {
	DEBUG_MAILBOX_VECTOR,              // Vector 33
	EFI_VECTOR_HANDOFF_DO_NOT_HOOK,
	EFI_DEBUG_AGENT_GUID
  },
  {
	0,
	EFI_VECTOR_HANDOFF_LAST_ENTRY,
	{ 0 }
  }
};

GLOBAL_REMOVE_IF_UNREFERENCED UINTN  mVectorHandoffInfoCount = sizeof(mVectorHandoffInfoDebugAgent) / sizeof(EFI_VECTOR_HANDOFF_INFO);

/**
  Calculate CRC16 for target data.

  @param[in]  Data              The target data.
  @param[in]  DataSize          The target data size.
  @param[in]  Crc               Initial CRC.

  @return UINT16     The CRC16 value.

**/
UINT16
CalculateCrc16(
	IN UINT8* Data,
	IN UINTN   DataSize,
	IN UINT16  Crc
)
{
	UINTN  Index;
	UINTN  BitIndex;

	for (Index = 0; Index < DataSize; Index++) {
		Crc ^= (UINT16)Data[Index];
		for (BitIndex = 0; BitIndex < 8; BitIndex++) {
			if ((Crc & 0x8000) != 0) {
				Crc <<= 1;
				Crc ^= 0x1021;
			}
			else {
				Crc <<= 1;
			}
		}
	}

	return Crc;
}

/**
  Read IDT entry to check if IDT entries are setup by Debug Agent.

  @retval  TRUE     IDT entries were setup by Debug Agent.
  @retval  FALSE    IDT entries were not setup by Debug Agent.

**/
BOOLEAN
IsDebugAgentInitialzed(
	VOID
)
{
	UINTN  InterruptHandler;

	InterruptHandler = (UINTN)GetExceptionHandlerInIdtEntry(0);
	if ((InterruptHandler >= 4) && (*(UINT32*)(InterruptHandler - 4) == AGENT_HANDLER_SIGNATURE)) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}


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
	//KdpDprintf(L"ImageContext.Pe32Data Start %p\r\n", Pe32Data);
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
VOID
EFIAPI
PeCoffLoaderRelocateImageExtraActionWindbg(
	IN OUT PE_COFF_LOADER_IMAGE_CONTEXT* ImageContext
)
{
	AsmWriteDr2((UINTN)ImageContext->ImageAddress);
	AsmWriteDr0(IMAGE_LOAD_SIGNATURE);
	return;
}



/**
  Find and report module image info to HOST.

  @param[in] AlignSize      Image aligned size.

**/
VOID
FindAndReportModuleImageInfo(
	IN UINTN  AlignSize
)
{
	UINT64                         Pe32Data;
	PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;

	//
	// Find Image Base
	//
	Pe32Data = PeCoffSearchImageBaseWindbg((UINTN)mErrorMsgVersionAlert);
	if (Pe32Data != 0) {
		ImageContext.ImageAddress = Pe32Data;
		//KdpDprintf(L"ImageContext.ImageAddress %p\r\n", ImageContext.ImageAddress);
		//ImageContext.PdbPointer = PeCoffLoaderGetPdbPointer((VOID*)(UINTN)ImageContext.ImageAddress);
		PeCoffLoaderRelocateImageExtraActionWindbg(&ImageContext);
	}
	return;
}


/**
  Find and report module image info to HOST.

  @param[in] AlignSize      Image aligned size.

**/
VOID
FindAndReportModuleImageInfoWindbg(
	IN UINTN  AlignSize, PUEFI_SYMBOLS_INFO pSyntheticSymbolInfo
)
{
	UINT64                         Pe32Data;
	PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;

	//
	// Find Image Base
	//
	Pe32Data = PeCoffSearchImageBaseWindbg((UINTN)mErrorMsgVersionAlert);
	if (Pe32Data != 0) {
		ImageContext.ImageAddress = Pe32Data;
		KdVersionBlock.KernBase = ImageContext.ImageAddress;
		KdVersionBlock.DebuggerDataList = ImageContext.ImageAddress;
		KdVersionBlock.PsLoadedModuleList = ImageContext.ImageAddress;
		//KdpDprintf(L"ImageContext.ImageAddress %p\r\n", ImageContext.ImageAddress);
		//ImageContext.PdbPointer = PeCoffLoaderGetPdbPointer((VOID*)(UINTN)ImageContext.ImageAddress);
		//PeCoffLoaderRelocateImageExtraAction(&ImageContext);

		WCHAR* pdbpath = GetModuleName((UINT8*)ImageContext.ImageAddress, &pSyntheticSymbolInfo->SymbolInfo.CheckSum, &pSyntheticSymbolInfo->SymbolInfo.SizeOfImage);
		if (pdbpath)
		{
			//KdpDprintf(L"%s\r\n", pdbpath);
			if (ForceConsoleOutput)
			{
				DEBUG((DEBUG_INFO, "%s\r\n", pdbpath));

			}
			hvwcscpy(pSyntheticSymbolInfo->SymbolPathBuffer, pdbpath);
		}
		pSyntheticSymbolInfo->SymbolInfo.BaseOfDll = (PVOID)ImageContext.ImageAddress;
		pSyntheticSymbolInfo->SymbolInfo.ProcessId = GetProcessorIndex();



	}
	return;
}

/**
  Trigger one software interrupt to debug agent to handle it.

  @param[in] Signature       Software interrupt signature.

**/
VOID
TriggerSoftInterrupt(
	IN UINT32  Signature
)
{
	UINTN  Dr0;
	UINTN  Dr1;

	//
	// Save Debug Register State
	//
	Dr0 = AsmReadDr0();
	Dr1 = AsmReadDr1();

	//
	// DR0 = Signature
	//
	AsmWriteDr0(SOFT_INTERRUPT_SIGNATURE);
	AsmWriteDr1(Signature);

	//
	// Do INT3 to communicate with HOST side
	//
	CpuBreakpoint();

	//
	// Restore Debug Register State only when Host didn't change it inside exception handler.
	//   Dr registers can only be changed by setting the HW breakpoint.
	//
	AsmWriteDr0(Dr0);
	AsmWriteDr1(Dr1);
}

/**
  Calculate Mailbox checksum and update the checksum field.

  @param[in]  Mailbox  Debug Agent Mailbox pointer.

**/
VOID
UpdateMailboxChecksum(
	IN DEBUG_AGENT_MAILBOX* Mailbox
)
{
	Mailbox->CheckSum = CalculateCheckSum8((UINT8*)Mailbox, sizeof(DEBUG_AGENT_MAILBOX) - 2);
}

/**
  Verify Mailbox checksum.

  If checksum error, print debug message and run init dead loop.

  @param[in]  Mailbox  Debug Agent Mailbox pointer.

**/
VOID
VerifyMailboxChecksum(
	IN DEBUG_AGENT_MAILBOX* Mailbox
)
{
	UINT8  CheckSum;

	CheckSum = CalculateCheckSum8((UINT8*)Mailbox, sizeof(DEBUG_AGENT_MAILBOX) - 2);
	//
	// The checksum updating process may be disturbed by hardware SMI, we need to check CheckSum field
	// and ToBeCheckSum field to validate the mail box.
	//
	if ((CheckSum != Mailbox->CheckSum) && (CheckSum != Mailbox->ToBeCheckSum)) {
		DEBUG((DEBUG_ERROR, "DebugAgent: Mailbox checksum error, stack or heap crashed!\n"));
		DEBUG((DEBUG_ERROR, "DebugAgent: CheckSum = %x, Mailbox->CheckSum = %x, Mailbox->ToBeCheckSum = %x\n", CheckSum, Mailbox->CheckSum, Mailbox->ToBeCheckSum));
		CpuDeadLoop();
	}
}

/**
  Update Mailbox content by index.

  @param[in]  Mailbox  Debug Agent Mailbox pointer.
  @param[in]  Index    Mailbox content index.
  @param[in]  Value    Value to be set into Mailbox.

**/
VOID
UpdateMailboxContent(
	IN DEBUG_AGENT_MAILBOX* Mailbox,
	IN UINTN                Index,
	IN UINT64               Value
)
{
	AcquireMpSpinLock(&mDebugMpContext.MailboxSpinLock);
	switch (Index) {
	case DEBUG_MAILBOX_DEBUG_FLAG_INDEX:
		Mailbox->ToBeCheckSum = Mailbox->CheckSum + CalculateSum8((UINT8*)&Mailbox->DebugFlag.Uint64, sizeof(UINT64))
			- CalculateSum8((UINT8*)&Value, sizeof(UINT64));
		Mailbox->DebugFlag.Uint64 = Value;
		break;
	case DEBUG_MAILBOX_DEBUG_PORT_HANDLE_INDEX:
		Mailbox->ToBeCheckSum = Mailbox->CheckSum + CalculateSum8((UINT8*)&Mailbox->DebugPortHandle, sizeof(UINTN))
			- CalculateSum8((UINT8*)&Value, sizeof(UINTN));
		Mailbox->DebugPortHandle = (UINTN)Value;
		break;
	case DEBUG_MAILBOX_EXCEPTION_BUFFER_POINTER_INDEX:
		Mailbox->ToBeCheckSum = Mailbox->CheckSum + CalculateSum8((UINT8*)&Mailbox->ExceptionBufferPointer, sizeof(UINTN))
			- CalculateSum8((UINT8*)&Value, sizeof(UINTN));
		Mailbox->ExceptionBufferPointer = (UINTN)Value;
		break;
	case DEBUG_MAILBOX_LAST_ACK:
		Mailbox->ToBeCheckSum = Mailbox->CheckSum + CalculateSum8((UINT8*)&Mailbox->LastAck, sizeof(UINT8))
			- CalculateSum8((UINT8*)&Value, sizeof(UINT8));
		Mailbox->LastAck = (UINT8)Value;
		break;
	case DEBUG_MAILBOX_SEQUENCE_NO_INDEX:
		Mailbox->ToBeCheckSum = Mailbox->CheckSum + CalculateSum8((UINT8*)&Mailbox->SequenceNo, sizeof(UINT8))
			- CalculateSum8((UINT8*)&Value, sizeof(UINT8));
		Mailbox->SequenceNo = (UINT8)Value;
		break;
	case DEBUG_MAILBOX_HOST_SEQUENCE_NO_INDEX:
		Mailbox->ToBeCheckSum = Mailbox->CheckSum + CalculateSum8((UINT8*)&Mailbox->HostSequenceNo, sizeof(UINT8))
			- CalculateSum8((UINT8*)&Value, sizeof(UINT8));
		Mailbox->HostSequenceNo = (UINT8)Value;
		break;
	case DEBUG_MAILBOX_DEBUG_TIMER_FREQUENCY:
		Mailbox->ToBeCheckSum = Mailbox->CheckSum + CalculateSum8((UINT8*)&Mailbox->DebugTimerFrequency, sizeof(UINT32))
			- CalculateSum8((UINT8*)&Value, sizeof(UINT32));
		Mailbox->DebugTimerFrequency = (UINT32)Value;
		break;
	}

	UpdateMailboxChecksum(Mailbox);
	ReleaseMpSpinLock(&mDebugMpContext.MailboxSpinLock);
}

/**
  Read data from debug device and save the data in buffer.

  Reads NumberOfBytes data bytes from a debug device into the buffer
  specified by Buffer. The number of bytes actually read is returned.
  If the return value is less than NumberOfBytes, then the rest operation failed.
  If NumberOfBytes is zero, then return 0.

  @param  Handle           Debug port handle.
  @param  Buffer           Pointer to the data buffer to store the data read from the debug device.
  @param  NumberOfBytes    Number of bytes which will be read.
  @param  Timeout          Timeout value for reading from debug device. It unit is Microsecond.

  @retval 0                Read data failed, no data is to be read.
  @retval >0               Actual number of bytes read from debug device.

**/
UINTN
DebugAgentReadBuffer(
	IN DEBUG_PORT_HANDLE  Handle,
	IN UINT8* Buffer,
	IN UINTN              NumberOfBytes,
	IN UINTN              Timeout
)
{
	UINTN   Index;
	UINT32  Begin;
	UINT32  TimeoutTicker;
	UINT32  TimerRound;
	UINT32  TimerFrequency;
	UINT32  TimerCycle;

	Begin = 0;
	TimeoutTicker = 0;
	TimerRound = 0;
	TimerFrequency = GetMailboxPointer()->DebugTimerFrequency;
	TimerCycle = GetApicTimerInitCount();

	if (Timeout != 0) {
		Begin = GetApicTimerCurrentCount();
		TimeoutTicker = (UINT32)DivU64x32(
			MultU64x64(
				TimerFrequency,
				Timeout
			),
			1000000u
		);
		TimerRound = (UINT32)DivU64x32Remainder(TimeoutTicker, TimerCycle / 2, &TimeoutTicker);
	}

	Index = 0;
	while (Index < NumberOfBytes) {
		if (DebugPortPollBuffer(Handle)) {
			DebugPortReadBuffer(Handle, Buffer + Index, 1, 0);
			Index++;
			continue;
		}

		if (Timeout != 0) {
			if (TimerRound == 0) {
				if (IsDebugTimerTimeout(TimerCycle, Begin, TimeoutTicker)) {
					//
					// If time out occurs.
					//
					return 0;
				}
			}
			else {
				if (IsDebugTimerTimeout(TimerCycle, Begin, TimerCycle / 2)) {
					TimerRound--;
					Begin = GetApicTimerCurrentCount();
				}
			}
		}
	}

	return Index;
}

/**
  Set debug flag in mailbox.

  @param[in]  FlagMask      Debug flag mask value.
  @param[in]  FlagValue     Debug flag value.

**/
VOID
SetDebugFlag(
	IN UINT64  FlagMask,
	IN UINT32  FlagValue
)
{
	DEBUG_AGENT_MAILBOX* Mailbox;
	UINT64               Data64;

	Mailbox = GetMailboxPointer();
	Data64 = (Mailbox->DebugFlag.Uint64 & ~FlagMask) |
		(LShiftU64((UINT64)FlagValue, LowBitSet64(FlagMask)) & FlagMask);
	UpdateMailboxContent(Mailbox, DEBUG_MAILBOX_DEBUG_FLAG_INDEX, Data64);
}

/**
  Get debug flag in mailbox.

  @param[in]  FlagMask      Debug flag mask value.

  @return Debug flag value.

**/
UINT32
GetDebugFlag(
	IN UINT64  FlagMask
)
{
	DEBUG_AGENT_MAILBOX* Mailbox;
	UINT32               DebugFlag;

	Mailbox = GetMailboxPointer();
	DebugFlag = (UINT32)RShiftU64(Mailbox->DebugFlag.Uint64 & FlagMask, LowBitSet64(FlagMask));

	return DebugFlag;
}

/**
  Send a debug message packet to the debug port.

  @param[in] Buffer  The debug message.
  @param[in] Length  The length of debug message.

**/
VOID
SendDebugMsgPacket(
	IN CHAR8* Buffer,
	IN UINTN  Length
)
{
	return;
	/*DEBUG_PACKET_HEADER  DebugHeader;
	DEBUG_PORT_HANDLE    Handle;

	Handle = GetDebugPortHandle();

	DebugHeader.StartSymbol = DEBUG_STARTING_SYMBOL_NORMAL;
	DebugHeader.Command = DEBUG_COMMAND_PRINT_MESSAGE;
	DebugHeader.Length = sizeof(DEBUG_PACKET_HEADER) + (UINT8)Length;
	DebugHeader.SequenceNo = 0xEE;
	DebugHeader.Crc = 0;
	DebugHeader.Crc = CalculateCrc16(
		(UINT8*)Buffer,
		Length,
		CalculateCrc16((UINT8*)&DebugHeader, sizeof(DEBUG_PACKET_HEADER), 0)
	);

	DebugPortWriteBuffer(Handle, (UINT8*)&DebugHeader, sizeof(DEBUG_PACKET_HEADER));
	DebugPortWriteBuffer(Handle, (UINT8*)Buffer, Length);*/
}

/**
  Prints a debug message to the debug port if the specified error level is enabled.

  If any bit in ErrorLevel is also set in Mainbox, then print the message specified
  by Format and the associated variable argument list to the debug port.

  @param[in] ErrorLevel  The error level of the debug message.
  @param[in] Format      Format string for the debug message to print.
  @param[in] ...         Variable argument list whose contents are accessed
						 based on the format string specified by Format.

**/
VOID
EFIAPI
DebugAgentMsgPrint(
	IN UINT8  ErrorLevel,
	IN CHAR8* Format,
	...
)
{
	CHAR8    Buffer[DEBUG_DATA_MAXIMUM_REAL_DATA];
	VA_LIST  Marker;

	//
	// Check driver debug mask value and global mask
	//
	if ((ErrorLevel & GetDebugFlag(DEBUG_AGENT_FLAG_PRINT_ERROR_LEVEL)) == 0) {
		return;
	}

	//
	// Convert the DEBUG() message to an ASCII String
	//
	VA_START(Marker, Format);
	AsciiVSPrint(Buffer, sizeof(Buffer), Format, Marker);
	VA_END(Marker);
	KdpDprintf(L"%a", Buffer);
	return;
	//SendDebugMsgPacket(Buffer, AsciiStrLen(Buffer));
}

/**
  Prints a debug message to the debug output device if the specified error level is enabled.

  If any bit in ErrorLevel is also set in DebugPrintErrorLevelLib function
  GetDebugPrintErrorLevel (), then print the message specified by Format and the
  associated variable argument list to the debug output device.

  If Format is NULL, then ASSERT().

  @param[in] ErrorLevel  The error level of the debug message.
  @param[in] IsSend      Flag of debug message to declare that the data is being sent or being received.
  @param[in] Data        Variable argument list whose contents are accessed
  @param[in] Length      based on the format string specified by Format.

**/
VOID
EFIAPI
DebugAgentDataMsgPrint(
	IN UINT8    ErrorLevel,
	IN BOOLEAN  IsSend,
	IN UINT8* Data,
	IN UINT8    Length
)
{
	CHAR8  Buffer[DEBUG_DATA_MAXIMUM_REAL_DATA];
	CHAR8* DestBuffer;
	//UINTN  Index;

	//
	// Check driver debug mask value and global mask
	//
	if ((ErrorLevel & GetDebugFlag(DEBUG_AGENT_FLAG_PRINT_ERROR_LEVEL)) == 0) {
		return;
	}

	DestBuffer = Buffer;
	if (IsSend) {
		DestBuffer += AsciiSPrint(DestBuffer, DEBUG_DATA_MAXIMUM_REAL_DATA, "Sent data [ ");
	}
	else {
		DestBuffer += AsciiSPrint(DestBuffer, DEBUG_DATA_MAXIMUM_REAL_DATA, "Received data [ ");
	}
	KdpDprintf(L"%a", DestBuffer);
	return;

	/*Index = 0;
	while (TRUE) {
		if (DestBuffer - Buffer > DEBUG_DATA_MAXIMUM_REAL_DATA - 6) {
			//
			// If there was no enough space in buffer, send out the debug message,
			// reserving 6 bytes is for the last data and end characters "]\n".
			//
			SendDebugMsgPacket(Buffer, DestBuffer - Buffer);
			DestBuffer = Buffer;
		}

		DestBuffer += AsciiSPrint(DestBuffer, DEBUG_DATA_MAXIMUM_REAL_DATA - (DestBuffer - Buffer), "%02x ", Data[Index]);
		Index++;
		if (Index >= Length) {
			//
			// The last character of debug message has been formatted in buffer
			//
			DestBuffer += AsciiSPrint(DestBuffer, DEBUG_DATA_MAXIMUM_REAL_DATA - (DestBuffer - Buffer), "]\n");
			SendDebugMsgPacket(Buffer, DestBuffer - Buffer);
			break;
		}
	}*/
}

/**
  Read remaining debug packet except for the start symbol

  @param[in]      Handle        Pointer to Debug Port handle.
  @param[in, out] DebugHeader   Debug header buffer including start symbol.

  @retval EFI_SUCCESS        Read the symbol in BreakSymbol.
  @retval EFI_CRC_ERROR      CRC check fail.
  @retval EFI_TIMEOUT        Timeout occurs when reading debug packet.
  @retval EFI_DEVICE_ERROR   Receive the old or response packet.

**/
EFI_STATUS
ReadRemainingBreakPacket(
	IN     DEBUG_PORT_HANDLE    Handle,
	IN OUT DEBUG_PACKET_HEADER* DebugHeader
)
{
	UINT16               Crc;
	DEBUG_AGENT_MAILBOX* Mailbox;

	//
	// Has received start symbol, try to read the rest part
	//
	if (DebugAgentReadBuffer(Handle, (UINT8*)DebugHeader + OFFSET_OF(DEBUG_PACKET_HEADER, Command), sizeof(DEBUG_PACKET_HEADER) - OFFSET_OF(DEBUG_PACKET_HEADER, Command), READ_PACKET_TIMEOUT) == 0) {
		//
		// Timeout occur, exit
		//
		DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "Timeout in Debug Timer interrupt\n");
		return EFI_TIMEOUT;
	}

	Crc = DebugHeader->Crc;
	DebugHeader->Crc = 0;
	if (CalculateCrc16((UINT8*)DebugHeader, DebugHeader->Length, 0) != Crc) {
		DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "Debug Timer CRC (%x) against (%x)\n", Crc, CalculateCrc16((UINT8*)&DebugHeader, DebugHeader->Length, 0));
		DebugAgentDataMsgPrint(DEBUG_AGENT_VERBOSE, FALSE, (UINT8*)DebugHeader, DebugHeader->Length);
		return EFI_CRC_ERROR;
	}

	Mailbox = GetMailboxPointer();
	if (IS_REQUEST(DebugHeader)) {
		if (DebugHeader->SequenceNo == (UINT8)(Mailbox->HostSequenceNo + 1)) {
			//
			// Only update HostSequenceNo for new command packet
			//
			UpdateMailboxContent(Mailbox, DEBUG_MAILBOX_HOST_SEQUENCE_NO_INDEX, DebugHeader->SequenceNo);
			return EFI_SUCCESS;
		}

		if (DebugHeader->SequenceNo == Mailbox->HostSequenceNo) {
			return EFI_SUCCESS;
		}
	}

	return EFI_DEVICE_ERROR;
}

/**
  Check if HOST is attached based on Mailbox.

  @retval TRUE        HOST is attached.
  @retval FALSE       HOST is not attached.

**/
BOOLEAN
IsHostAttached(
	VOID
)
{
	return TRUE;
	//return (BOOLEAN)(GetDebugFlag(DEBUG_AGENT_FLAG_HOST_ATTACHED) == 1);
}

/**
  Set HOST connect flag in Mailbox.

  @param[in] Attached        Attach status.

**/
VOID
SetHostAttached(
	IN BOOLEAN  Attached
)
{
	DebugAgentMsgPrint(DEBUG_AGENT_INFO, "Attach status is %d\n", Attached);
	SetDebugFlag(DEBUG_AGENT_FLAG_HOST_ATTACHED, (UINT32)Attached);
}

/**
  Set debug setting of Debug Agent in Mailbox.

  @param DebugSetting         Pointer to Debug Setting defined by transfer protocol.

  @retval RETURN_SUCCESS      The setting is set successfully.
  @retval RETURN_UNSUPPORTED  The Key value is not supported.

**/
RETURN_STATUS
SetDebugSetting(
	IN DEBUG_DATA_SET_DEBUG_SETTING* DebugSetting
)
{
	RETURN_STATUS  Status;

	Status = RETURN_SUCCESS;
	switch (DebugSetting->Key) {
	case DEBUG_AGENT_SETTING_SMM_ENTRY_BREAK:
		SetDebugFlag(DEBUG_AGENT_FLAG_BREAK_ON_NEXT_SMI, DebugSetting->Value);
		break;
	case DEBUG_AGENT_SETTING_PRINT_ERROR_LEVEL:
		SetDebugFlag(DEBUG_AGENT_FLAG_PRINT_ERROR_LEVEL, DebugSetting->Value);
		break;
	case DEBUG_AGENT_SETTING_BOOT_SCRIPT_ENTRY_BREAK:
		SetDebugFlag(DEBUG_AGENT_FLAG_BREAK_BOOT_SCRIPT, DebugSetting->Value);
		break;
	default:
		Status = RETURN_UNSUPPORTED;
	}

	return Status;
}

/**
  Execute GO command.

  @param[in] CpuContext        Pointer to saved CPU context.

**/
VOID
CommandGo(
	IN DEBUG_CPU_CONTEXT* CpuContext
)
{
	IA32_EFLAGS32* Eflags;

	Eflags = (IA32_EFLAGS32*)&CpuContext->Eflags;
	Eflags->Bits.TF = 0;
	Eflags->Bits.RF = 1;
}


/**
  Set debug register for hardware breakpoint.

  @param[in] CpuContext      Pointer to saved CPU context.
  @param[in] SetHwBreakpoint Hardware breakpoint to be set.

**/
VOID
SetDebugRegister(
	IN DEBUG_CPU_CONTEXT* CpuContext,
	IN DEBUG_DATA_SET_HW_BREAKPOINT* SetHwBreakpoint
)
{
	UINT8  RegisterIndex;
	UINTN  Dr7Value;

	RegisterIndex = SetHwBreakpoint->Type.Index;

	//
	// Set debug address
	//
	*((UINTN*)&CpuContext->Dr0 + RegisterIndex) = (UINTN)SetHwBreakpoint->Address;

	Dr7Value = CpuContext->Dr7;

	//
	// Enable Gx, Lx
	//
	Dr7Value |= (UINTN)(0x3 << (RegisterIndex * 2));
	//
	// Set RWx and Lenx
	//
	Dr7Value &= (UINTN)(~(0xf << (16 + RegisterIndex * 4)));
	Dr7Value |= (UINTN)((SetHwBreakpoint->Type.Length << 2) | SetHwBreakpoint->Type.Access) << (16 + RegisterIndex * 4);
	//
	// Enable GE, LE
	//
	Dr7Value |= 0x300;

	CpuContext->Dr7 = Dr7Value;
}

/**
  Clear debug register for hardware breakpoint.

  @param[in] CpuContext        Pointer to saved CPU context.
  @param[in] ClearHwBreakpoint Hardware breakpoint to be cleared.

**/
VOID
ClearDebugRegister(
	IN DEBUG_CPU_CONTEXT* CpuContext,
	IN DEBUG_DATA_CLEAR_HW_BREAKPOINT* ClearHwBreakpoint
)
{
	if ((ClearHwBreakpoint->IndexMask & BIT0) != 0) {
		CpuContext->Dr0 = 0;
		CpuContext->Dr7 &= (UINTN)(~(0x3 << 0));
	}

	if ((ClearHwBreakpoint->IndexMask & BIT1) != 0) {
		CpuContext->Dr1 = 0;
		CpuContext->Dr7 &= (UINTN)(~(0x3 << 2));
	}

	if ((ClearHwBreakpoint->IndexMask & BIT2) != 0) {
		CpuContext->Dr2 = 0;
		CpuContext->Dr7 &= (UINTN)(~(0x3 << 4));
	}

	if ((ClearHwBreakpoint->IndexMask & BIT3) != 0) {
		CpuContext->Dr3 = 0;
		CpuContext->Dr7 &= (UINTN)(~(0x3 << 6));
	}
}

/**
  Return the offset of FP / MMX / XMM registers in the FPU saved state by register index.

  @param[in]  Index    Register index.
  @param[out] Width    Register width returned.

  @return Offset in the FPU Save State.

**/
UINT16
ArchReadFxStatOffset(
	IN  UINT8  Index,
	OUT UINT8* Width
)
{
	if (Index < SOFT_DEBUGGER_REGISTER_ST0) {
		switch (Index) {
		case SOFT_DEBUGGER_REGISTER_FP_FCW:
			*Width = (UINT8)sizeof(UINT16);
			return OFFSET_OF(DEBUG_DATA_FX_SAVE_STATE, Fcw);

		case SOFT_DEBUGGER_REGISTER_FP_FSW:
			*Width = (UINT8)sizeof(UINT16);
			return OFFSET_OF(DEBUG_DATA_FX_SAVE_STATE, Fsw);

		case SOFT_DEBUGGER_REGISTER_FP_FTW:
			*Width = (UINT8)sizeof(UINT16);
			return OFFSET_OF(DEBUG_DATA_FX_SAVE_STATE, Ftw);

		case SOFT_DEBUGGER_REGISTER_FP_OPCODE:
			*Width = (UINT8)sizeof(UINT16);
			return OFFSET_OF(DEBUG_DATA_FX_SAVE_STATE, Opcode);

		case SOFT_DEBUGGER_REGISTER_FP_EIP:
			*Width = (UINT8)sizeof(UINT32);
			return OFFSET_OF(DEBUG_DATA_FX_SAVE_STATE, Eip);

		case SOFT_DEBUGGER_REGISTER_FP_CS:
			*Width = (UINT8)sizeof(UINT16);
			return OFFSET_OF(DEBUG_DATA_FX_SAVE_STATE, Cs);

		case SOFT_DEBUGGER_REGISTER_FP_DATAOFFSET:
			*Width = (UINT8)sizeof(UINT32);
			return OFFSET_OF(DEBUG_DATA_FX_SAVE_STATE, DataOffset);

		case SOFT_DEBUGGER_REGISTER_FP_DS:
			*Width = (UINT8)sizeof(UINT16);
			return OFFSET_OF(DEBUG_DATA_FX_SAVE_STATE, Ds);

		case SOFT_DEBUGGER_REGISTER_FP_MXCSR:
			*Width = (UINT8)sizeof(UINT32);
			return OFFSET_OF(DEBUG_DATA_FX_SAVE_STATE, Mxcsr);

		case SOFT_DEBUGGER_REGISTER_FP_MXCSR_MASK:
			*Width = (UINT8)sizeof(UINT32);
			return OFFSET_OF(DEBUG_DATA_FX_SAVE_STATE, Mxcsr_Mask);
		}
	}

	if (Index <= SOFT_DEBUGGER_REGISTER_ST7) {
		*Width = 10;
	}
	else if (Index <= SOFT_DEBUGGER_REGISTER_XMM15) {
		*Width = 16;
	}
	else {
		//
		// MMX register
		//
		*Width = 8;
		Index -= SOFT_DEBUGGER_REGISTER_MM0 - SOFT_DEBUGGER_REGISTER_ST0;
	}

	return OFFSET_OF(DEBUG_DATA_FX_SAVE_STATE, St0Mm0) + (Index - SOFT_DEBUGGER_REGISTER_ST0) * 16;
}

/**
  Return the pointer of the register value in the CPU saved context.

  @param[in]  CpuContext         Pointer to saved CPU context.
  @param[in]  Index              Register index value.
  @param[out] Width              Data width to read.

  @return The pointer in the CPU saved context.

**/
UINT8*
ArchReadRegisterBuffer(
	IN DEBUG_CPU_CONTEXT* CpuContext,
	IN UINT8              Index,
	OUT UINT8* Width
)
{
	UINT8* Buffer;

	if (Index < SOFT_DEBUGGER_REGISTER_FP_BASE) {
		Buffer = (UINT8*)CpuContext + OFFSET_OF(DEBUG_CPU_CONTEXT, Dr0) + Index * sizeof(UINTN);
		*Width = (UINT8)sizeof(UINTN);
	}
	else {
		//
		// FPU/MMX/XMM registers
		//
		Buffer = (UINT8*)CpuContext + OFFSET_OF(DEBUG_CPU_CONTEXT, FxSaveState) + ArchReadFxStatOffset(Index, Width);
	}

	return Buffer;
}

/**
  Send the packet without data to HOST.

  @param[in] CommandType    Type of Command.
  @param[in] SequenceNo     Sequence number.

**/
VOID
SendPacketWithoutData(
	IN UINT8  CommandType,
	IN UINT8  SequenceNo
)
{
	DEBUG_PACKET_HEADER  DebugHeader;
	DEBUG_PORT_HANDLE    Handle;

	Handle = GetDebugPortHandle();

	DebugHeader.StartSymbol = DEBUG_STARTING_SYMBOL_NORMAL;
	DebugHeader.Command = CommandType;
	DebugHeader.Length = sizeof(DEBUG_PACKET_HEADER);
	DebugHeader.SequenceNo = SequenceNo;
	DebugHeader.Crc = 0;
	DebugHeader.Crc = CalculateCrc16((UINT8*)&DebugHeader, sizeof(DEBUG_PACKET_HEADER), 0);

	DebugAgentDataMsgPrint(DEBUG_AGENT_VERBOSE, TRUE, (UINT8*)&DebugHeader, DebugHeader.Length);
	DebugPortWriteBuffer(Handle, (UINT8*)&DebugHeader, DebugHeader.Length);
}

/**
  Send acknowledge packet to HOST.

  @param[in] AckCommand    Type of Acknowledge packet.

**/
VOID
SendAckPacket(
	IN UINT8  AckCommand
)
{
	return;
	/*UINT8                SequenceNo;
	DEBUG_AGENT_MAILBOX* Mailbox;

	if (AckCommand != DEBUG_COMMAND_OK) {
		//
		// This is not ACK OK packet
		//
		DebugAgentMsgPrint(DEBUG_AGENT_ERROR, "Send ACK(%d)\n", AckCommand);
	}

	Mailbox = GetMailboxPointer();
	SequenceNo = Mailbox->HostSequenceNo;
	DebugAgentMsgPrint(DEBUG_AGENT_INFO, "SendAckPacket: SequenceNo = %x\n", SequenceNo);
	SendPacketWithoutData(AckCommand, SequenceNo);
	UpdateMailboxContent(Mailbox, DEBUG_MAILBOX_LAST_ACK, AckCommand);*/
}

/**
  Decompress the Data in place.

  @param[in, out] Data   The compressed data buffer.
						 The buffer is assumed large enough to hold the uncompressed data.
  @param[in]      Length The length of the compressed data buffer.

  @return   The length of the uncompressed data buffer.
**/
UINT8
DecompressDataInPlace(
	IN OUT UINT8* Data,
	IN UINTN      Length
)
{
	UINTN   Index;
	UINT16  LastChar;
	UINTN   LastCharCount;
	UINT8   CurrentChar;

	LastChar = (UINT16)-1;
	LastCharCount = 0;
	for (Index = 0; Index < Length; Index++) {
		CurrentChar = Data[Index];
		if (LastCharCount == 2) {
			LastCharCount = 0;
			CopyMem(&Data[Index + CurrentChar], &Data[Index + 1], Length - Index - 1);
			SetMem(&Data[Index], CurrentChar, (UINT8)LastChar);
			LastChar = (UINT16)-1;
			Index += CurrentChar - 1;
			Length += CurrentChar - 1;
		}
		else {
			if (LastChar != CurrentChar) {
				LastCharCount = 0;
			}

			LastCharCount++;
			LastChar = CurrentChar;
		}
	}

	ASSERT(Length <= DEBUG_DATA_MAXIMUM_REAL_DATA);

	return (UINT8)Length;
}

/**
  Receive valid packet from HOST.

  @param[out] InputPacket         Buffer to receive packet.
  @param[out] BreakReceived       TRUE means break-in symbol received.
								  FALSE means break-in symbol not received.
  @param[out] IncompatibilityFlag If IncompatibilityFlag is not NULL, return
								  TRUE:  Compatible packet received.
								  FALSE: Incompatible packet received.
  @param[in]  Timeout             Time out value to wait for acknowledge from HOST.
								  The unit is microsecond.
  @param[in]  SkipStartSymbol     TRUE:  Skip time out when reading start symbol.
								  FALSE: Does not Skip time out when reading start symbol.

  @retval RETURN_SUCCESS   A valid package was received in InputPacket.
  @retval RETURN_TIMEOUT   Timeout occurs.

**/
RETURN_STATUS
ReceivePacket(
	OUT UINT8* InputPacket,
	OUT BOOLEAN* BreakReceived,
	OUT BOOLEAN* IncompatibilityFlag  OPTIONAL,
	IN  UINTN    Timeout,
	IN  BOOLEAN  SkipStartSymbol
)
{
	DEBUG_PACKET_HEADER* DebugHeader;
	UINTN                Received;
	DEBUG_PORT_HANDLE    Handle;
	UINT16               Crc;
	UINTN                TimeoutForStartSymbol;

	Handle = GetDebugPortHandle();
	if (SkipStartSymbol) {
		TimeoutForStartSymbol = 0;
	}
	else {
		TimeoutForStartSymbol = Timeout;
	}

	DebugHeader = (DEBUG_PACKET_HEADER*)InputPacket;
	while (TRUE) {
		//
		// Find the valid start symbol
		//
		Received = DebugAgentReadBuffer(Handle, &DebugHeader->StartSymbol, sizeof(DebugHeader->StartSymbol), TimeoutForStartSymbol);
		if (Received < sizeof(DebugHeader->StartSymbol)) {
			DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "DebugAgentReadBuffer(StartSymbol) timeout\n");
			return RETURN_TIMEOUT;
		}

		if ((DebugHeader->StartSymbol != DEBUG_STARTING_SYMBOL_NORMAL) && (DebugHeader->StartSymbol != DEBUG_STARTING_SYMBOL_COMPRESS)) {
			DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "Invalid start symbol received [%02x]\n", DebugHeader->StartSymbol);
			continue;
		}

		//
		// Read Package header till field Length
		//
		Received = DebugAgentReadBuffer(
			Handle,
			(UINT8*)DebugHeader + OFFSET_OF(DEBUG_PACKET_HEADER, Command),
			OFFSET_OF(DEBUG_PACKET_HEADER, Length) + sizeof(DebugHeader->Length) - sizeof(DebugHeader->StartSymbol),
			Timeout
		);
		if (Received == 0) {
			DebugAgentMsgPrint(DEBUG_AGENT_ERROR, "DebugAgentReadBuffer(Command) timeout\n");
			return RETURN_TIMEOUT;
		}

		if (DebugHeader->Length < sizeof(DEBUG_PACKET_HEADER)) {
			if (IncompatibilityFlag != NULL) {
				//
				// This is one old version debug packet format, set Incompatibility flag
				//
				*IncompatibilityFlag = TRUE;
			}
			else {
				//
				// Skip the bad small packet
				//
				continue;
			}
		}
		else {
			//
			// Read the payload data include the CRC field
			//
			Received = DebugAgentReadBuffer(Handle, &DebugHeader->SequenceNo, (UINT8)(DebugHeader->Length - OFFSET_OF(DEBUG_PACKET_HEADER, SequenceNo)), Timeout);
			if (Received == 0) {
				DebugAgentMsgPrint(DEBUG_AGENT_ERROR, "DebugAgentReadBuffer(SequenceNo) timeout\n");
				return RETURN_TIMEOUT;
			}

			//
			// Calculate the CRC of Debug Packet
			//
			Crc = DebugHeader->Crc;
			DebugHeader->Crc = 0;
			if (Crc == CalculateCrc16((UINT8*)DebugHeader, DebugHeader->Length, 0)) {
				break;
			}

			DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "CRC Error (received CRC is %x)\n", Crc);
			DebugAgentDataMsgPrint(DEBUG_AGENT_VERBOSE, FALSE, (UINT8*)DebugHeader, DebugHeader->Length);
		}
	}

	DebugAgentDataMsgPrint(DEBUG_AGENT_VERBOSE, FALSE, (UINT8*)DebugHeader, DebugHeader->Length);

	if (DebugHeader->StartSymbol == DEBUG_STARTING_SYMBOL_COMPRESS) {
		DebugHeader->StartSymbol = DEBUG_STARTING_SYMBOL_NORMAL;
		DebugHeader->Length = DecompressDataInPlace(
			(UINT8*)(DebugHeader + 1),
			DebugHeader->Length - sizeof(DEBUG_PACKET_HEADER)
		) + sizeof(DEBUG_PACKET_HEADER);
	}

	return RETURN_SUCCESS;
}

/**
  Receive acknowledge packet OK from HOST in specified time.

  @param[in]  Command             The command type issued by TARGET.
  @param[in]  Timeout             Time out value to wait for acknowledge from HOST.
								  The unit is microsecond.
  @param[out] BreakReceived       If BreakReceived is not NULL,
								  TRUE is returned if break-in symbol received.
								  FALSE is returned if break-in symbol not received.
  @param[out] IncompatibilityFlag If IncompatibilityFlag is not NULL, return
								  TRUE:  Compatible packet received.
								  FALSE: Incompatible packet received.

  @retval  RETURN_SUCCESS   Succeed to receive acknowledge packet from HOST,
							the type of acknowledge packet saved in Ack.
  @retval  RETURN_TIMEOUT   Specified timeout value was up.

**/
RETURN_STATUS
SendCommandAndWaitForAckOK(
	IN  UINT8    Command,
	IN  UINTN    Timeout,
	OUT BOOLEAN* BreakReceived  OPTIONAL,
	OUT BOOLEAN* IncompatibilityFlag OPTIONAL
)
{
	return 0;
	/*RETURN_STATUS        Status;
	UINT8                InputPacketBuffer[DEBUG_DATA_UPPER_LIMIT];
	DEBUG_PACKET_HEADER* DebugHeader;
	UINT8                SequenceNo;
	UINT8                HostSequenceNo;
	UINT8                RetryCount;

	RetryCount = 3;
	DebugHeader = (DEBUG_PACKET_HEADER*)InputPacketBuffer;
	Status = RETURN_TIMEOUT;
	while (RetryCount > 0) {
		SequenceNo = GetMailboxPointer()->SequenceNo;
		HostSequenceNo = GetMailboxPointer()->HostSequenceNo;
		SendPacketWithoutData(Command, SequenceNo);
		Status = ReceivePacket((UINT8*)DebugHeader, BreakReceived, IncompatibilityFlag, Timeout, FALSE);
		if (Status == RETURN_TIMEOUT) {
			if (Command == DEBUG_COMMAND_INIT_BREAK) {
				RetryCount--;
			}
			else {
				DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "TARGET: Timeout when waiting for ACK packet.\n");
			}

			continue;
		}

		ASSERT_EFI_ERROR(Status);
		//
		// Status == RETURN_SUCCESS
		//
		if ((DebugHeader->Command == DEBUG_COMMAND_OK) && (DebugHeader->SequenceNo == SequenceNo)) {
			//
			// Received Ack OK
			//
			UpdateMailboxContent(GetMailboxPointer(), DEBUG_MAILBOX_SEQUENCE_NO_INDEX, ++SequenceNo);
			return Status;
		}

		if ((DebugHeader->Command == DEBUG_COMMAND_GO) && ((DebugHeader->SequenceNo == HostSequenceNo) || (Command == DEBUG_COMMAND_INIT_BREAK))) {
			//
			// Received Old GO
			//
			if (Command == DEBUG_COMMAND_INIT_BREAK) {
				DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "TARGET: Receive GO() in last boot\n");
			}

			SendPacketWithoutData(DEBUG_COMMAND_OK, DebugHeader->SequenceNo);
		}
	}

	ASSERT(Command == DEBUG_COMMAND_INIT_BREAK);
	return Status;*/
}

/**
  Get current break cause.

  @param[in] Vector      Vector value of exception or interrupt.
  @param[in] CpuContext  Pointer to save CPU context.

  @return The type of break cause defined by XXXX

**/
UINT8
GetBreakCause(
	IN UINTN              Vector,
	IN DEBUG_CPU_CONTEXT* CpuContext
)
{
	UINT8  Cause;

	Cause = DEBUG_DATA_BREAK_CAUSE_UNKNOWN;

	switch (Vector) {
	case DEBUG_INT1_VECTOR:
	case DEBUG_INT3_VECTOR:

		if (Vector == DEBUG_INT1_VECTOR) {
			//
			// INT 1
			//
			if ((CpuContext->Dr6 & BIT14) != 0) {
				Cause = DEBUG_DATA_BREAK_CAUSE_STEPPING;
				//
				// DR6.BIT14 Indicates (when set) that the debug exception was
				// triggered by the single step execution mode.
				// The single-step mode is the highest priority debug exception.
				// This is single step, no need to check DR0, to ensure single step
				// work in PeCoffExtraActionLib (right after triggering a breakpoint
				// to report image load/unload).
				//
				return Cause;
			}
			else {
				Cause = DEBUG_DATA_BREAK_CAUSE_HW_BREAKPOINT;
			}
		}
		else {
			//
			// INT 3
			//
			Cause = DEBUG_DATA_BREAK_CAUSE_SW_BREAKPOINT;
		}

		switch (CpuContext->Dr0) {
		case IMAGE_LOAD_SIGNATURE:
		case IMAGE_UNLOAD_SIGNATURE:
		{

			//if (CpuContext->Dr3 == IO_PORT_BREAKPOINT_ADDRESS) {
			Cause = (UINT8)((CpuContext->Dr0 == IMAGE_LOAD_SIGNATURE) ?
				DEBUG_DATA_BREAK_CAUSE_IMAGE_LOAD : DEBUG_DATA_BREAK_CAUSE_IMAGE_UNLOAD);
			//}

			break;
		}
		case SOFT_INTERRUPT_SIGNATURE:

			if (CpuContext->Dr1 == MEMORY_READY_SIGNATURE) {
				Cause = DEBUG_DATA_BREAK_CAUSE_MEMORY_READY;
				CpuContext->Dr0 = 0;
			}
			else if (CpuContext->Dr1 == SYSTEM_RESET_SIGNATURE) {
				Cause = DEBUG_DATA_BREAK_CAUSE_SYSTEM_RESET;
				CpuContext->Dr0 = 0;
			}

			break;

		default:
			break;
		}

		break;

	case DEBUG_TIMER_VECTOR:
		Cause = DEBUG_DATA_BREAK_CAUSE_USER_HALT;
		break;

	default:
		if (Vector < 20) {
			if (GetDebugFlag(DEBUG_AGENT_FLAG_STEPPING) == 1) {
				//
				// If stepping command is executing
				//
				Cause = DEBUG_DATA_BREAK_CAUSE_STEPPING;
			}
			else {
				Cause = DEBUG_DATA_BREAK_CAUSE_EXCEPTION;
			}
		}

		break;
	}

	return Cause;
}

/**
  Copy memory from source to destination with specified width.

  @param[out] Dest        A pointer to the destination buffer of the memory copy.
  @param[in]  Src         A pointer to the source buffer of the memory copy.
  @param[in]  Count       The number of data with specified width to copy from source to destination.
  @param[in]  Width       Data width in byte.

**/
VOID
CopyMemByWidth(
	OUT UINT8* Dest,
	IN  UINT8* Src,
	IN  UINT16  Count,
	IN  UINT8   Width
)
{
	UINT8* Destination;
	UINT8* Source;
	INT8   Step;

	if (Src > Dest) {
		Destination = Dest;
		Source = Src;
		Step = Width;
	}
	else {
		//
		// Copy memory from tail to avoid memory overlap
		//
		Destination = Dest + (Count - 1) * Width;
		Source = Src + (Count - 1) * Width;
		Step = -Width;
	}

	while (Count-- != 0) {
		switch (Width) {
		case 1:
			*(UINT8*)Destination = MmioRead8((UINTN)Source);
			break;
		case 2:
			*(UINT16*)Destination = MmioRead16((UINTN)Source);
			break;
		case 4:
			*(UINT32*)Destination = MmioRead32((UINTN)Source);
			break;
		case 8:
			*(UINT64*)Destination = MmioRead64((UINTN)Source);
			break;
		default:
			ASSERT(FALSE);
		}

		Source += Step;
		Destination += Step;
	}
}

/**
  Compress the data buffer but do not modify the original buffer.

  The compressed data is directly send to the debug channel.
  Compressing in place doesn't work because the data may become larger
  during compressing phase. ("3 3 ..." --> "3 3 0 ...")
  The routine is expected to be called three times:
  1. Compute the length of the compressed data buffer;
  2. Compute the CRC of the compressed data buffer;
  3. Compress the data and send to the debug channel.

  @param[in]  Handle           The debug channel handle to send the compressed data buffer.
  @param[in]  Data             The data buffer.
  @param[in]  Length           The length of the data buffer.
  @param[in]  Send             TRUE to send the compressed data buffer.
  @param[out] CompressedLength Return the length of the compressed data buffer.
							   It may be larger than the Length in some cases.
  @param[out] CompressedCrc    Return the CRC of the compressed data buffer.
**/
VOID
CompressData(
	IN  DEBUG_PORT_HANDLE  Handle,
	IN  UINT8* Data,
	IN  UINT8              Length,
	IN  BOOLEAN            Send,
	OUT UINTN* CompressedLength   OPTIONAL,
	OUT UINT16* CompressedCrc      OPTIONAL
)
{
	UINTN  Index;
	UINT8  LastChar;
	UINT8  LastCharCount;
	UINT8  CurrentChar;
	UINTN  CompressedIndex;

	ASSERT(Length > 0);
	LastChar = Data[0] + 1; // Just ensure it's different from the first byte.
	LastCharCount = 0;

	for (Index = 0, CompressedIndex = 0; Index <= Length; Index++) {
		if (Index < Length) {
			CurrentChar = Data[Index];
		}
		else {
			CurrentChar = (UINT8)LastChar + 1;  // just ensure it's different from LastChar
		}

		if (LastChar != CurrentChar) {
			if (LastCharCount == 1) {
				CompressedIndex++;
				if (CompressedCrc != NULL) {
					*CompressedCrc = CalculateCrc16(&LastChar, 1, *CompressedCrc);
				}

				if (Send) {
					DebugPortWriteBuffer(Handle, &LastChar, 1);
				}
			}
			else if (LastCharCount >= 2) {
				CompressedIndex += 3;
				LastCharCount -= 2;
				if (CompressedCrc != NULL) {
					*CompressedCrc = CalculateCrc16(&LastChar, 1, *CompressedCrc);
					*CompressedCrc = CalculateCrc16(&LastChar, 1, *CompressedCrc);
					*CompressedCrc = CalculateCrc16(&LastCharCount, 1, *CompressedCrc);
				}

				if (Send) {
					DebugPortWriteBuffer(Handle, &LastChar, 1);
					DebugPortWriteBuffer(Handle, &LastChar, 1);
					DebugPortWriteBuffer(Handle, &LastCharCount, 1);
				}
			}

			LastCharCount = 0;
		}

		LastCharCount++;
		LastChar = CurrentChar;
	}

	if (CompressedLength != NULL) {
		*CompressedLength = CompressedIndex;
	}
}

/**
  Read memory with specified width and send packet with response data to HOST.

  @param[in] Data        Pointer to response data buffer.
  @param[in] Count       The number of data with specified Width.
  @param[in] Width       Data width in byte.
  @param[in] DebugHeader Pointer to a buffer for creating response packet and receiving ACK packet,
						 to minimize the stack usage.

  @retval RETURN_SUCCESS      Response data was sent successfully.

**/
RETURN_STATUS
ReadMemoryAndSendResponsePacket(
	IN UINT8* Data,
	IN UINT16               Count,
	IN UINT8                Width,
	IN DEBUG_PACKET_HEADER* DebugHeader
)
{
	RETURN_STATUS      Status;
	BOOLEAN            LastPacket;
	DEBUG_PORT_HANDLE  Handle;
	UINT8              SequenceNo;
	UINTN              RemainingDataSize;
	UINT8              CurrentDataSize;
	UINTN              CompressedDataSize;

	Handle = GetDebugPortHandle();

	RemainingDataSize = Count * Width;
	while (TRUE) {
		SequenceNo = GetMailboxPointer()->HostSequenceNo;
		if (RemainingDataSize <= DEBUG_DATA_MAXIMUM_REAL_DATA) {
			//
			// If the remaining data is less one real packet size, this is the last data packet
			//
			CurrentDataSize = (UINT8)RemainingDataSize;
			LastPacket = TRUE;
			DebugHeader->Command = DEBUG_COMMAND_OK;
		}
		else {
			//
			// Data is too larger to be sent in one packet, calculate the actual data size could
			// be sent in one Maximum data packet
			//
			CurrentDataSize = (DEBUG_DATA_MAXIMUM_REAL_DATA / Width) * Width;
			LastPacket = FALSE;
			DebugHeader->Command = DEBUG_COMMAND_IN_PROGRESS;
		}

		//
		// Construct the rest Debug header
		//
		DebugHeader->StartSymbol = DEBUG_STARTING_SYMBOL_NORMAL;
		DebugHeader->Length = CurrentDataSize + sizeof(DEBUG_PACKET_HEADER);
		DebugHeader->SequenceNo = SequenceNo;
		DebugHeader->Crc = 0;
		CopyMemByWidth((UINT8*)(DebugHeader + 1), Data, CurrentDataSize / Width, Width);

		//
		// Compression/decompression support was added since revision 0.4.
		// Revision 0.3 shouldn't compress the packet.
		//
		//if (PcdGet32(PcdTransferProtocolRevision) >= DEBUG_AGENT_REVISION_04) {
		if (TRUE) {
			//
			// Get the compressed data size without modifying the packet.
			//
			CompressData(
				Handle,
				(UINT8*)(DebugHeader + 1),
				CurrentDataSize,
				FALSE,
				&CompressedDataSize,
				NULL
			);
		}
		else {
			CompressedDataSize = CurrentDataSize;
		}

		if (CompressedDataSize < CurrentDataSize) {
			DebugHeader->Length = (UINT8)CompressedDataSize + sizeof(DEBUG_PACKET_HEADER);
			DebugHeader->StartSymbol = DEBUG_STARTING_SYMBOL_COMPRESS;
			//
			// Compute the CRC of the packet head without modifying the packet.
			//
			DebugHeader->Crc = CalculateCrc16((UINT8*)DebugHeader, sizeof(DEBUG_PACKET_HEADER), 0);
			CompressData(
				Handle,
				(UINT8*)(DebugHeader + 1),
				CurrentDataSize,
				FALSE,
				NULL,
				&DebugHeader->Crc
			);
			//
			// Send out the packet head.
			//
			DebugPortWriteBuffer(Handle, (UINT8*)DebugHeader, sizeof(DEBUG_PACKET_HEADER));
			//
			// Compress and send out the packet data.
			//
			CompressData(
				Handle,
				(UINT8*)(DebugHeader + 1),
				CurrentDataSize,
				TRUE,
				NULL,
				NULL
			);
		}
		else {
			//
			// Calculate and fill the checksum, DebugHeader->Crc should be 0 before invoking CalculateCrc16 ()
			//
			DebugHeader->Crc = CalculateCrc16((UINT8*)DebugHeader, DebugHeader->Length, 0);

			DebugAgentDataMsgPrint(DEBUG_AGENT_VERBOSE, TRUE, (UINT8*)DebugHeader, DebugHeader->Length);

			DebugPortWriteBuffer(Handle, (UINT8*)DebugHeader, DebugHeader->Length);
		}

		while (TRUE) {
			Status = ReceivePacket((UINT8*)DebugHeader, NULL, NULL, READ_PACKET_TIMEOUT, FALSE);
			if (Status == RETURN_TIMEOUT) {
				DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "TARGET: Timeout in SendDataResponsePacket()\n");
				break;
			}

			if ((DebugHeader->Command == DEBUG_COMMAND_OK) && (DebugHeader->SequenceNo == SequenceNo) && LastPacket) {
				//
				// If this is the last packet, return RETURN_SUCCESS.
				//
				return RETURN_SUCCESS;
			}

			if ((DebugHeader->Command == DEBUG_COMMAND_CONTINUE) && (DebugHeader->SequenceNo == (UINT8)(SequenceNo + 1))) {
				//
				// Calculate the rest data size
				//
				Data += CurrentDataSize;
				RemainingDataSize -= CurrentDataSize;
				UpdateMailboxContent(GetMailboxPointer(), DEBUG_MAILBOX_HOST_SEQUENCE_NO_INDEX, DebugHeader->SequenceNo);
				break;
			}

			if (DebugHeader->SequenceNo >= SequenceNo) {
				DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "TARGET: Received one old or new command(SequenceNo is %x, last SequenceNo is %x)\n", SequenceNo, DebugHeader->SequenceNo);
				break;
			}
		}
	}
}

/**
  Send packet with response data to HOST.

  @param[in]      Data        Pointer to response data buffer.
  @param[in]      DataSize    Size of response data in byte.
  @param[in, out] DebugHeader Pointer to a buffer for creating response packet and receiving ACK packet,
							  to minimize the stack usage.

  @retval RETURN_SUCCESS      Response data was sent successfully.

**/
RETURN_STATUS
SendDataResponsePacket(
	IN UINT8* Data,
	IN UINT16                   DataSize,
	IN OUT DEBUG_PACKET_HEADER* DebugHeader
)
{
	return ReadMemoryAndSendResponsePacket(Data, DataSize, 1, DebugHeader);
}

/**
  Try to attach the HOST.

  Send init break packet to HOST:
  If no acknowledge received in specified Timeout, return RETURN_TIMEOUT.
  If received acknowledge, check the revision of HOST.
  Set Attach Flag if attach successfully.

  @param[in]  BreakCause     Break cause of this break event.
  @param[in]  Timeout        Time out value to wait for acknowledge from HOST.
							 The unit is microsecond.
  @param[out] BreakReceived  If BreakReceived is not NULL,
							 TRUE is returned if break-in symbol received.
							 FALSE is returned if break-in symbol not received.
**/
RETURN_STATUS
AttachHost(
	IN  UINT8    BreakCause,
	IN  UINTN    Timeout,
	OUT BOOLEAN* BreakReceived
)
{
	return RETURN_SUCCESS;


	/*
	 RETURN_STATUS      Status;
	DEBUG_PORT_HANDLE  Handle;
	BOOLEAN            IncompatibilityFlag;
	 *IncompatibilityFlag = FALSE;
	Handle = GetDebugPortHandle();

	//
	// Send init break and wait ack in Timeout
	//
	DebugPortWriteBuffer(Handle, (UINT8*)mErrorMsgSendInitPacket, AsciiStrLen(mErrorMsgSendInitPacket));
	if (BreakCause == DEBUG_DATA_BREAK_CAUSE_SYSTEM_RESET) {
		Status = SendCommandAndWaitForAckOK(DEBUG_COMMAND_INIT_BREAK, Timeout, BreakReceived, &IncompatibilityFlag);
	}
	else {
		Status = SendCommandAndWaitForAckOK(DEBUG_COMMAND_ATTACH_BREAK, Timeout, BreakReceived, &IncompatibilityFlag);
	}

	if (IncompatibilityFlag) {
		//
		// If the incompatible Debug Packet received, the HOST should be running transfer protocol before PcdTransferProtocolRevision.
		// It could be UDK Debugger for Windows v1.1/v1.2 or for Linux v0.8/v1.2.
		//
		DebugPortWriteBuffer(Handle, (UINT8*)mErrorMsgVersionAlert, AsciiStrLen(mErrorMsgVersionAlert));
		CpuDeadLoop();
	}

	if (RETURN_ERROR(Status)) {
		DebugPortWriteBuffer(Handle, (UINT8*)mErrorMsgConnectFail, AsciiStrLen(mErrorMsgConnectFail));
	}
	else {
		DebugPortWriteBuffer(Handle, (UINT8*)mErrorMsgConnectOK, AsciiStrLen(mErrorMsgConnectOK));
		//
		// Set Attach flag
		//
		SetHostAttached(TRUE);
	}

	return Status;*/
}

/**
  Send Break point packet to HOST.

  Only the first breaking processor could sent BREAK_POINT packet.

  @param[in]  BreakCause     Break cause of this break event.
  @param[in]  ProcessorIndex Processor index value.
  @param[out] BreakReceived  If BreakReceived is not NULL,
							 TRUE is returned if break-in symbol received.
							 FALSE is returned if break-in symbol not received.

**/
VOID
SendBreakPacketToHost(
	IN  UINT8    BreakCause,
	IN  UINT32   ProcessorIndex,
	OUT BOOLEAN* BreakReceived
)
{
	UINT8              InputCharacter;
	DEBUG_PORT_HANDLE  Handle;

	Handle = GetDebugPortHandle();

	if (IsHostAttached()) {
		DebugAgentMsgPrint(DEBUG_AGENT_INFO, "processor[%x]:Send Break Packet to HOST.\n", ProcessorIndex);
		SendCommandAndWaitForAckOK(DEBUG_COMMAND_BREAK_POINT, READ_PACKET_TIMEOUT, BreakReceived, NULL);
	}
	else {
		DebugAgentMsgPrint(DEBUG_AGENT_INFO, "processor[%x]:Try to attach HOST.\n", ProcessorIndex);
		//
		// If HOST is not attached, try to attach it firstly.
		//
		//
		// Poll Attach symbols from HOST and ack OK
		//
		do {
			DebugAgentReadBuffer(Handle, &InputCharacter, 1, 0);
		} while (InputCharacter != DEBUG_STARTING_SYMBOL_ATTACH);

		SendAckPacket(DEBUG_COMMAND_OK);

		//
		// Try to attach HOST
		//
		while (AttachHost(BreakCause, 0, NULL) != RETURN_SUCCESS) {
		}
	}
}

/**
  The main function to process communication with HOST.

  It received the command packet from HOST, and sent response data packet to HOST.

  @param[in]      Vector         Vector value of exception or interrupt.
  @param[in, out] CpuContext     Pointer to saved CPU context.
  @param[in]      BreakReceived  TRUE means break-in symbol received.
								 FALSE means break-in symbol not received.

**/
VOID
CommandCommunicationOld(
	IN     UINTN              Vector,
	IN OUT DEBUG_CPU_CONTEXT* CpuContext,
	IN     BOOLEAN            BreakReceived
)
{
	RETURN_STATUS                      Status;
	UINT8                              InputPacketBuffer[DEBUG_DATA_UPPER_LIMIT + sizeof(UINT64) - 1];
	DEBUG_PACKET_HEADER* DebugHeader;
	UINT8                              Width;
	UINT8                              Data8;
	UINT32                             Data32;
	UINT64                             Data64;
	DEBUG_DATA_READ_MEMORY* MemoryRead;
	DEBUG_DATA_WRITE_MEMORY* MemoryWrite;
	DEBUG_DATA_READ_IO* IoRead;
	DEBUG_DATA_WRITE_IO* IoWrite;
	DEBUG_DATA_READ_REGISTER* RegisterRead;
	DEBUG_DATA_WRITE_REGISTER* RegisterWrite;
	UINT8* RegisterBuffer;
	DEBUG_DATA_READ_MSR* MsrRegisterRead;
	DEBUG_DATA_WRITE_MSR* MsrRegisterWrite;
	DEBUG_DATA_CPUID* Cpuid;
	DEBUG_DATA_RESPONSE_BREAK_CAUSE    BreakCause;
	DEBUG_DATA_RESPONSE_CPUID          CpuidResponse;
	DEBUG_DATA_SEARCH_SIGNATURE* SearchSignature;
	DEBUG_DATA_RESPONSE_GET_EXCEPTION  Exception;
	DEBUG_DATA_RESPONSE_GET_REVISION   DebugAgentRevision;
	DEBUG_DATA_SET_VIEWPOINT* SetViewPoint;
	BOOLEAN                            HaltDeferred;
	UINT32                             ProcessorIndex;
	DEBUG_AGENT_EXCEPTION_BUFFER       AgentExceptionBuffer;
	UINT32                             IssuedViewPoint;
	DEBUG_AGENT_MAILBOX* Mailbox;
	UINT8* AlignedDataPtr;

	ProcessorIndex = 0;
	IssuedViewPoint = 0;
	HaltDeferred = BreakReceived;

	if (MultiProcessorDebugSupport()) {
		ProcessorIndex = GetProcessorIndex();
		SetCpuStopFlagByIndex(ProcessorIndex, TRUE);
		if (mDebugMpContext.ViewPointIndex == ProcessorIndex) {
			//
			// Only the current view processor could set AgentInProgress Flag.
			//
			IssuedViewPoint = ProcessorIndex;
		}
	}

	if (IssuedViewPoint == ProcessorIndex) {
		//
		// Set AgentInProgress Flag.
		//
		SetDebugFlag(DEBUG_AGENT_FLAG_AGENT_IN_PROGRESS, 1);
	}

	while (TRUE) {
		if (MultiProcessorDebugSupport()) {
			//
			// Check if the current processor is HOST view point
			//
			if (mDebugMpContext.ViewPointIndex != ProcessorIndex) {
				if (mDebugMpContext.RunCommandSet) {
					//
					// If HOST view point sets RUN flag, run GO command to leave
					//
					SetCpuStopFlagByIndex(ProcessorIndex, FALSE);
					CommandGo(CpuContext);
					break;
				}
				else {
					//
					// Run into loop again
					//
					CpuPause();
					continue;
				}
			}
		}

		AcquireMpSpinLock(&mDebugMpContext.DebugPortSpinLock);

		DebugHeader = (DEBUG_PACKET_HEADER*)InputPacketBuffer;

		DebugAgentMsgPrint(DEBUG_AGENT_INFO, "TARGET: Try to get command from HOST...\n");
		Status = ReceivePacket((UINT8*)DebugHeader, &BreakReceived, NULL, READ_PACKET_TIMEOUT, TRUE);
		if ((Status != RETURN_SUCCESS) || !IS_REQUEST(DebugHeader)) {
			DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "TARGET: Get command[%x] sequenceno[%x] returned status is [%x] \n", DebugHeader->Command, DebugHeader->SequenceNo, Status);
			DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "TARGET: Get command failed or it's response packet not expected! \n");
			ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
			continue;
		}

		Mailbox = GetMailboxPointer();
		if (DebugHeader->SequenceNo == Mailbox->HostSequenceNo) {
			DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "TARGET: Receive one old command[%x] against command[%x]\n", DebugHeader->SequenceNo, Mailbox->HostSequenceNo);
			SendAckPacket(Mailbox->LastAck);
			ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
			continue;
		}
		else if (DebugHeader->SequenceNo == (UINT8)(Mailbox->HostSequenceNo + 1)) {
			UpdateMailboxContent(Mailbox, DEBUG_MAILBOX_HOST_SEQUENCE_NO_INDEX, (UINT8)DebugHeader->SequenceNo);
		}
		else {
			DebugAgentMsgPrint(DEBUG_AGENT_WARNING, "Receive one invalid command[%x] against command[%x]\n", DebugHeader->SequenceNo, Mailbox->HostSequenceNo);
			ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
			continue;
		}

		//
		// Save CPU content before executing HOST command
		//
		UpdateMailboxContent(Mailbox, DEBUG_MAILBOX_EXCEPTION_BUFFER_POINTER_INDEX, (UINT64)(UINTN)&AgentExceptionBuffer.JumpBuffer);
		if (SetJump(&AgentExceptionBuffer.JumpBuffer) != 0) {
			//
			// If HOST command failed, continue to wait for HOST's next command
			// If needed, agent could send exception info to HOST.
			//
			SendAckPacket(DEBUG_COMMAND_ABORT);
			ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
			continue;
		}

		DebugAgentMsgPrint(DEBUG_AGENT_INFO, "Processor[%x]:Received one command(%x)\n", mDebugMpContext.ViewPointIndex, DebugHeader->Command);

		switch (DebugHeader->Command) {
		case DEBUG_COMMAND_HALT:
			SendAckPacket(DEBUG_COMMAND_HALT_DEFERRED);
			HaltDeferred = TRUE;
			BreakReceived = FALSE;
			Status = RETURN_SUCCESS;
			break;

		case DEBUG_COMMAND_RESET:
			SendAckPacket(DEBUG_COMMAND_OK);
			SendAckPacket(DEBUG_COMMAND_OK);
			SendAckPacket(DEBUG_COMMAND_OK);
			ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);

			ResetCold();
			//
			// Assume system resets in 2 seconds, otherwise send TIMEOUT packet.
			// PCD can be used if 2 seconds isn't long enough for some platforms.
			//
			MicroSecondDelay(2000000);
			UpdateMailboxContent(Mailbox, DEBUG_MAILBOX_HOST_SEQUENCE_NO_INDEX, Mailbox->HostSequenceNo + 1);
			SendAckPacket(DEBUG_COMMAND_TIMEOUT);
			SendAckPacket(DEBUG_COMMAND_TIMEOUT);
			SendAckPacket(DEBUG_COMMAND_TIMEOUT);
			break;

		case DEBUG_COMMAND_GO:
			CommandGo(CpuContext);
			//
			// Clear Dr0 to avoid to be recognized as IMAGE_LOAD/_UNLOAD again when hitting a breakpoint after GO
			// If HOST changed Dr0 before GO, we will not change Dr0 here
			//
			Data8 = GetBreakCause(Vector, CpuContext);
			if ((Data8 == DEBUG_DATA_BREAK_CAUSE_IMAGE_LOAD) || (Data8 == DEBUG_DATA_BREAK_CAUSE_IMAGE_UNLOAD)) {
				CpuContext->Dr0 = 0;
			}

			if (!HaltDeferred) {
				//
				// If no HALT command received when being in-active mode
				//
				if (MultiProcessorDebugSupport()) {
					Data32 = FindNextPendingBreakCpu();
					if (Data32 != -1) {
						//
						// If there are still others processors being in break state,
						// send OK packet to HOST to finish this go command
						//
						SendAckPacket(DEBUG_COMMAND_OK);
						CpuPause();
						//
						// Set current view to the next breaking processor
						//
						mDebugMpContext.ViewPointIndex = Data32;
						mDebugMpContext.BreakAtCpuIndex = mDebugMpContext.ViewPointIndex;
						SetCpuBreakFlagByIndex(mDebugMpContext.ViewPointIndex, FALSE);
						//
						// Send break packet to HOST to let HOST break again
						//
						SendBreakPacketToHost(DEBUG_DATA_BREAK_CAUSE_UNKNOWN, mDebugMpContext.BreakAtCpuIndex, &BreakReceived);
						//
						// Continue to run into loop to read command packet from HOST
						//
						ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
						break;
					}

					//
					// If no else processor break, set stop bitmask,
					// and set Running flag for all processors.
					//
					SetCpuStopFlagByIndex(ProcessorIndex, FALSE);
					SetCpuRunningFlag(TRUE);
					CpuPause();
					//
					// Wait for all processors are in running state
					//
					while (TRUE) {
						if (IsAllCpuRunning()) {
							break;
						}
					}

					//
					// Set BSP to be current view point.
					//
					SetDebugViewPoint(mDebugMpContext.BspIndex);
					CpuPause();
					//
					// Clear breaking processor index and running flag
					//
					mDebugMpContext.BreakAtCpuIndex = (UINT32)(-1);
					SetCpuRunningFlag(FALSE);
				}

				//
				// Send OK packet to HOST to finish this go command
				//
				SendAckPacket(DEBUG_COMMAND_OK);

				ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);

				if (!IsHostAttached()) {
					UpdateMailboxContent(Mailbox, DEBUG_MAILBOX_SEQUENCE_NO_INDEX, 0);
					UpdateMailboxContent(Mailbox, DEBUG_MAILBOX_HOST_SEQUENCE_NO_INDEX, 0);
				}

				return;
			}
			else {
				//
				// If received HALT command, need to defer the GO command
				//
				SendAckPacket(DEBUG_COMMAND_HALT_PROCESSED);
				HaltDeferred = FALSE;

				Vector = DEBUG_TIMER_VECTOR;
			}

			break;

		case DEBUG_COMMAND_BREAK_CAUSE:
			BreakCause.StopAddress = CpuContext->Eip;
			if (MultiProcessorDebugSupport() && (ProcessorIndex != mDebugMpContext.BreakAtCpuIndex)) {
				BreakCause.Cause = GetBreakCause(DEBUG_TIMER_VECTOR, CpuContext);
			}
			else {
				BreakCause.Cause = GetBreakCause(Vector, CpuContext);
			}

			SendDataResponsePacket((UINT8*)&BreakCause, (UINT16)sizeof(DEBUG_DATA_RESPONSE_BREAK_CAUSE), DebugHeader);
			break;

		case DEBUG_COMMAND_SET_HW_BREAKPOINT:
			SetDebugRegister(CpuContext, (DEBUG_DATA_SET_HW_BREAKPOINT*)(DebugHeader + 1));
			SendAckPacket(DEBUG_COMMAND_OK);
			break;

		case DEBUG_COMMAND_CLEAR_HW_BREAKPOINT:
			ClearDebugRegister(CpuContext, (DEBUG_DATA_CLEAR_HW_BREAKPOINT*)(DebugHeader + 1));
			SendAckPacket(DEBUG_COMMAND_OK);
			break;

		case DEBUG_COMMAND_SINGLE_STEPPING:
			CommandStepping(CpuContext);
			//
			// Clear Dr0 to avoid to be recognized as IMAGE_LOAD/_UNLOAD again when hitting a breakpoint after GO
			// If HOST changed Dr0 before GO, we will not change Dr0 here
			//
			Data8 = GetBreakCause(Vector, CpuContext);
			if ((Data8 == DEBUG_DATA_BREAK_CAUSE_IMAGE_LOAD) || (Data8 == DEBUG_DATA_BREAK_CAUSE_IMAGE_UNLOAD)) {
				CpuContext->Dr0 = 0;
			}

			mDebugMpContext.BreakAtCpuIndex = (UINT32)(-1);
			ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
			//
			// Executing stepping command directly without sending ACK packet,
			// ACK packet will be sent after stepping done.
			//
			return;

		case DEBUG_COMMAND_SET_SW_BREAKPOINT:
			Data64 = (UINTN)(((DEBUG_DATA_SET_SW_BREAKPOINT*)(DebugHeader + 1))->Address);
			Data8 = *(UINT8*)(UINTN)Data64;
			*(UINT8*)(UINTN)Data64 = DEBUG_SW_BREAKPOINT_SYMBOL;
			Status = SendDataResponsePacket((UINT8*)&Data8, (UINT16)sizeof(UINT8), DebugHeader);
			break;

		case DEBUG_COMMAND_READ_MEMORY:
			MemoryRead = (DEBUG_DATA_READ_MEMORY*)(DebugHeader + 1);
			Status = ReadMemoryAndSendResponsePacket((UINT8*)(UINTN)MemoryRead->Address, MemoryRead->Count, MemoryRead->Width, DebugHeader);
			break;

		case DEBUG_COMMAND_WRITE_MEMORY:
			MemoryWrite = (DEBUG_DATA_WRITE_MEMORY*)(DebugHeader + 1);
			//
			// Copy data into one memory with 8-byte alignment address
			//
			AlignedDataPtr = ALIGN_POINTER((UINT8*)&MemoryWrite->Data, sizeof(UINT64));
			if (AlignedDataPtr != (UINT8*)&MemoryWrite->Data) {
				CopyMem(AlignedDataPtr, (UINT8*)&MemoryWrite->Data, MemoryWrite->Count * MemoryWrite->Width);
			}

			CopyMemByWidth((UINT8*)(UINTN)MemoryWrite->Address, AlignedDataPtr, MemoryWrite->Count, MemoryWrite->Width);
			SendAckPacket(DEBUG_COMMAND_OK);
			break;

		case DEBUG_COMMAND_READ_IO:
			IoRead = (DEBUG_DATA_READ_IO*)(DebugHeader + 1);
			switch (IoRead->Width) {
			case 1:
				Data64 = IoRead8((UINTN)IoRead->Port);
				break;
			case 2:
				Data64 = IoRead16((UINTN)IoRead->Port);
				break;
			case 4:
				Data64 = IoRead32((UINTN)IoRead->Port);
				break;
			case 8:
				Data64 = IoRead64((UINTN)IoRead->Port);
				break;
			default:
				Data64 = (UINT64)-1;
			}

			Status = SendDataResponsePacket((UINT8*)&Data64, IoRead->Width, DebugHeader);
			break;

		case DEBUG_COMMAND_WRITE_IO:
			IoWrite = (DEBUG_DATA_WRITE_IO*)(DebugHeader + 1);
			switch (IoWrite->Width) {
			case 1:
				Data64 = IoWrite8((UINTN)IoWrite->Port, *(UINT8*)&IoWrite->Data);
				break;
			case 2:
				Data64 = IoWrite16((UINTN)IoWrite->Port, *(UINT16*)&IoWrite->Data);
				break;
			case 4:
				Data64 = IoWrite32((UINTN)IoWrite->Port, *(UINT32*)&IoWrite->Data);
				break;
			case 8:
				Data64 = IoWrite64((UINTN)IoWrite->Port, *(UINT64*)&IoWrite->Data);
				break;
			default:
				Data64 = (UINT64)-1;
			}

			SendAckPacket(DEBUG_COMMAND_OK);
			break;

		case DEBUG_COMMAND_READ_ALL_REGISTERS:
			Status = SendDataResponsePacket((UINT8*)CpuContext, sizeof(*CpuContext), DebugHeader);
			break;

		case DEBUG_COMMAND_READ_REGISTER:
			RegisterRead = (DEBUG_DATA_READ_REGISTER*)(DebugHeader + 1);

			if (RegisterRead->Index <= SOFT_DEBUGGER_REGISTER_MAX) {
				RegisterBuffer = ArchReadRegisterBuffer(CpuContext, RegisterRead->Index, &Width);
				Status = SendDataResponsePacket(RegisterBuffer, Width, DebugHeader);
			}
			else {
				Status = RETURN_UNSUPPORTED;
			}

			break;

		case DEBUG_COMMAND_WRITE_REGISTER:
			RegisterWrite = (DEBUG_DATA_WRITE_REGISTER*)(DebugHeader + 1);
			if (RegisterWrite->Index <= SOFT_DEBUGGER_REGISTER_MAX) {
				RegisterBuffer = ArchReadRegisterBuffer(CpuContext, RegisterWrite->Index, &Width);
				ASSERT(Width == RegisterWrite->Length);
				CopyMem(RegisterBuffer, RegisterWrite->Data, Width);
				SendAckPacket(DEBUG_COMMAND_OK);
			}
			else {
				Status = RETURN_UNSUPPORTED;
			}

			break;

		case DEBUG_COMMAND_ARCH_MODE:
			Data8 = DEBUG_ARCH_SYMBOL;
			Status = SendDataResponsePacket((UINT8*)&Data8, (UINT16)sizeof(UINT8), DebugHeader);
			break;

		case DEBUG_COMMAND_READ_MSR:
			MsrRegisterRead = (DEBUG_DATA_READ_MSR*)(DebugHeader + 1);
			Data64 = AsmReadMsr64(MsrRegisterRead->Index);
			Status = SendDataResponsePacket((UINT8*)&Data64, (UINT16)sizeof(UINT64), DebugHeader);
			break;

		case DEBUG_COMMAND_WRITE_MSR:
			MsrRegisterWrite = (DEBUG_DATA_WRITE_MSR*)(DebugHeader + 1);
			AsmWriteMsr64(MsrRegisterWrite->Index, MsrRegisterWrite->Value);
			SendAckPacket(DEBUG_COMMAND_OK);
			break;

		case DEBUG_COMMAND_SET_DEBUG_SETTING:
			Status = SetDebugSetting((DEBUG_DATA_SET_DEBUG_SETTING*)(DebugHeader + 1));
			if (Status == RETURN_SUCCESS) {
				SendAckPacket(DEBUG_COMMAND_OK);
			}

			break;

		case DEBUG_COMMAND_GET_REVISION:
			// DebugAgentRevision.Revision = PcdGet32(PcdTransferProtocolRevision);
			DebugAgentRevision.Revision = DEBUG_AGENT_REVISION_04;
			DebugAgentRevision.Capabilities = DEBUG_AGENT_CAPABILITIES;
			Status = SendDataResponsePacket((UINT8*)&DebugAgentRevision, (UINT16)sizeof(DEBUG_DATA_RESPONSE_GET_REVISION), DebugHeader);
			break;

		case DEBUG_COMMAND_GET_EXCEPTION:
			Exception.ExceptionNum = (UINT8)Vector;
			Exception.ExceptionData = (UINT32)CpuContext->ExceptionData;
			Status = SendDataResponsePacket((UINT8*)&Exception, (UINT16)sizeof(DEBUG_DATA_RESPONSE_GET_EXCEPTION), DebugHeader);
			break;

		case DEBUG_COMMAND_SET_VIEWPOINT:
			SetViewPoint = (DEBUG_DATA_SET_VIEWPOINT*)(DebugHeader + 1);
			if (MultiProcessorDebugSupport()) {
				if (IsCpuStopped(SetViewPoint->ViewPoint)) {
					SetDebugViewPoint(SetViewPoint->ViewPoint);
					SendAckPacket(DEBUG_COMMAND_OK);
				}
				else {
					//
					// If CPU is not halted
					//
					SendAckPacket(DEBUG_COMMAND_NOT_SUPPORTED);
				}
			}
			else if (SetViewPoint->ViewPoint == 0) {
				SendAckPacket(DEBUG_COMMAND_OK);
			}
			else {
				SendAckPacket(DEBUG_COMMAND_NOT_SUPPORTED);
			}

			break;

		case DEBUG_COMMAND_GET_VIEWPOINT:
			Data32 = mDebugMpContext.ViewPointIndex;
			SendDataResponsePacket((UINT8*)&Data32, (UINT16)sizeof(UINT32), DebugHeader);
			break;

		case DEBUG_COMMAND_MEMORY_READY:
			Data8 = (UINT8)GetDebugFlag(DEBUG_AGENT_FLAG_MEMORY_READY);
			SendDataResponsePacket(&Data8, (UINT16)sizeof(UINT8), DebugHeader);
			break;

		case DEBUG_COMMAND_DETACH:
			SetHostAttached(FALSE);
			SendAckPacket(DEBUG_COMMAND_OK);
			break;

		case DEBUG_COMMAND_CPUID:
			Cpuid = (DEBUG_DATA_CPUID*)(DebugHeader + 1);
			AsmCpuidEx(
				Cpuid->Eax,
				Cpuid->Ecx,
				&CpuidResponse.Eax,
				&CpuidResponse.Ebx,
				&CpuidResponse.Ecx,
				&CpuidResponse.Edx
			);
			SendDataResponsePacket((UINT8*)&CpuidResponse, (UINT16)sizeof(CpuidResponse), DebugHeader);
			break;

		case DEBUG_COMMAND_SEARCH_SIGNATURE:
			SearchSignature = (DEBUG_DATA_SEARCH_SIGNATURE*)(DebugHeader + 1);
			if ((SearchSignature->Alignment != 0) &&
				(SearchSignature->Alignment == GetPowerOfTwo32(SearchSignature->Alignment))
				)
			{
				if (SearchSignature->Positive) {
					for (
						Data64 = ALIGN_VALUE((UINTN)SearchSignature->Start, SearchSignature->Alignment);
						Data64 <= SearchSignature->Start + SearchSignature->Count - SearchSignature->DataLength;
						Data64 += SearchSignature->Alignment
						)
					{
						if (CompareMem((VOID*)(UINTN)Data64, &SearchSignature->Data, SearchSignature->DataLength) == 0) {
							break;
						}
					}

					if (Data64 > SearchSignature->Start + SearchSignature->Count - SearchSignature->DataLength) {
						Data64 = (UINT64)-1;
					}
				}
				else {
					for (
						Data64 = ALIGN_VALUE((UINTN)SearchSignature->Start - SearchSignature->Alignment, SearchSignature->Alignment);
						Data64 >= SearchSignature->Start - SearchSignature->Count;
						Data64 -= SearchSignature->Alignment
						)
					{
						if (CompareMem((VOID*)(UINTN)Data64, &SearchSignature->Data, SearchSignature->DataLength) == 0) {
							break;
						}
					}

					if (Data64 < SearchSignature->Start - SearchSignature->Count) {
						Data64 = (UINT64)-1;
					}
				}

				SendDataResponsePacket((UINT8*)&Data64, (UINT16)sizeof(Data64), DebugHeader);
			}
			else {
				Status = RETURN_UNSUPPORTED;
			}

			break;

		default:
			SendAckPacket(DEBUG_COMMAND_NOT_SUPPORTED);
			break;
		}

		if (Status == RETURN_UNSUPPORTED) {
			SendAckPacket(DEBUG_COMMAND_NOT_SUPPORTED);
		}
		else if (Status != RETURN_SUCCESS) {
			SendAckPacket(DEBUG_COMMAND_ABORT);
		}

		ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
		CpuPause();
	}
}



BOOLEAN
NTAPI
KdpReport(IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN SecondChanceException, DEBUG_CPU_CONTEXT* CpuContext)
{
	BOOLEAN Enable, Handled;
	//PKPRCB Prcb;
	CONTEXT ContextFrame = { 0 };
	NTSTATUS ExceptionCode;

	/*
	 * Determine whether to pass the exception to the debugger.
	 * First, check if this is a "debug exception", meaning breakpoint
	 * (including debug service), single step and assertion failure exceptions.
	 */
	ExceptionCode = ExceptionRecord->ExceptionCode;
	if ((ExceptionCode == STATUS_BREAKPOINT) ||
		(ExceptionCode == STATUS_SINGLE_STEP) ||
		(ExceptionCode == STATUS_ASSERTION_FAILURE))
	{
		/* This is a debug exception; we always pass them to the debugger */
	}
	else if (NtGlobalFlag & FLG_STOP_ON_EXCEPTION)
	{
		/*
		 * Not a debug exception, but the stop-on-exception flag is set,
		 * meaning the debugger requests that we pass it first chance
		 * exceptions. However, some exceptions are always passed to the
		 * exception handler first, namely exceptions with a code that isn't
		 * an error or warning code, and also exceptions with the special
		 * STATUS_PORT_DISCONNECTED code (an error code).
		 */
		if ((SecondChanceException == FALSE) &&
			((ExceptionCode == STATUS_PORT_DISCONNECTED) ||
				(NT_SUCCESS(ExceptionCode))))
		{
			/* Let the exception handler, if any, try to handle it */
			return FALSE;
		}
	}
	else if (SecondChanceException == FALSE)
	{
		/*
		 * This isn't a debug exception and the stop-on-exception flag isn't set,
		 * so don't bother handling it
		 */
		return FALSE;
	}

	/* Enter the debugger */
	Enable = KdEnterDebugger(TrapFrame, ExceptionFrame);

	/*
	 * Get the KPRCB and save the CPU Control State manually instead of
	 * using KiSaveProcessorState, since we already have a valid CONTEXT.
	 */
	 //Prcb = KeGetCurrentPrcb();
	 //KiSaveProcessorControlState(&Prcb->ProcessorState);
	 /*KdpMoveMemory(&Prcb->ProcessorState.ContextFrame,
		 ContextRecord,
		 sizeof(CONTEXT));*/

	KdpMoveMemory(&ContextFrame,
		ContextRecord,
		sizeof(CONTEXT));

	/* Report the new state */
	//&Prcb->ProcessorState.
	Handled = KdpReportExceptionStateChange(ExceptionRecord,
		&ContextFrame,
		SecondChanceException, CpuContext);

	/* Now restore the processor state, manually again. */
	/*KdpMoveMemory(ContextRecord,
		&Prcb->ProcessorState.ContextFrame,
		sizeof(CONTEXT));*/
	KdpMoveMemory(ContextRecord,
		&ContextFrame,
		sizeof(CONTEXT));
	//KiRestoreProcessorControlState(&Prcb->ProcessorState);

	/* Exit the debugger and clear the CTRL-C state */
	KdExitDebugger(Enable);
	KdpControlCPressed = FALSE;
	return Handled;
}


BOOLEAN
NTAPI
KdpTrap(IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN SecondChanceException, DEBUG_CPU_CONTEXT* CpuContext)
{
	BOOLEAN Unload;
	ULONG_PTR ProgramCounter;
	BOOLEAN Handled;
	NTSTATUS ReturnStatus;
	USHORT ReturnLength;

	if (ForceConsoleOutput)
	{
		DEBUG((DEBUG_INFO, "KdpTrap %08x %08x\r\n", ExceptionRecord->ExceptionCode, ExceptionRecord->ExceptionInformation[0]));
	}
	/*
	 * Check if we got a STATUS_BREAKPOINT with a SubID for Print, Prompt or
	 * Load/Unload symbols. Make sure it isn't a software breakpoints as those
	 * are handled by KdpReport.
	 */
	if ((ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT) &&
		(ExceptionRecord->ExceptionInformation[0] != BREAKPOINT_BREAK))
	{
		/* Save Program Counter */
		ProgramCounter = KeGetContextPc(ContextRecord);

		/* Check what kind of operation was requested from us */
		Unload = FALSE;
		switch (ExceptionRecord->ExceptionInformation[0])
		{
			/* DbgPrint */
		case BREAKPOINT_PRINT:

			/* Call the worker routine */
			ReturnStatus = KdpPrint((ULONG)KdpGetParameterThree(ContextRecord),
				(ULONG)KdpGetParameterFour(ContextRecord),
				(PCHAR)ExceptionRecord->ExceptionInformation[1],
				(USHORT)ExceptionRecord->ExceptionInformation[2],
				PreviousMode,
				TrapFrame,
				ExceptionFrame,
				&Handled);

			/* Update the return value for the caller */
			KeSetContextReturnRegister(ContextRecord, ReturnStatus);
			break;

			/* DbgPrompt */
		case BREAKPOINT_PROMPT:

			/* Call the worker routine */
			ReturnLength = KdpPrompt((PCHAR)ExceptionRecord->ExceptionInformation[1],
				(USHORT)ExceptionRecord->ExceptionInformation[2],
				(PCHAR)KdpGetParameterThree(ContextRecord),
				(USHORT)KdpGetParameterFour(ContextRecord),
				PreviousMode,
				TrapFrame,
				ExceptionFrame);
			Handled = TRUE;

			/* Update the return value for the caller */
			KeSetContextReturnRegister(ContextRecord, ReturnLength);
			break;

			/* DbgUnLoadImageSymbols */
		case BREAKPOINT_UNLOAD_SYMBOLS:
		{
			/* Drop into the load case below, with the unload parameter */
			Unload = TRUE;
			break;
		}
		/* DbgLoadImageSymbols */
		case BREAKPOINT_LOAD_SYMBOLS:
		{
			//KdpDprintf(L"KdpSymbol %a\r\n", ((PSTRING)ExceptionRecord->ExceptionInformation[1])->Buffer);
			/* Call the worker routine */
			KdpSymbol((PSTRING)ExceptionRecord->ExceptionInformation[1],
				(PKD_SYMBOLS_INFO)ExceptionRecord->ExceptionInformation[2],
				Unload,
				PreviousMode,
				ContextRecord,
				TrapFrame,
				ExceptionFrame, CpuContext, FALSE);
			Handled = TRUE;
			break;
		}
		/* DbgCommandString */
		case BREAKPOINT_COMMAND_STRING:

			/* Call the worker routine */
			KdpCommandString((PSTRING)ExceptionRecord->ExceptionInformation[1],
				(PSTRING)ExceptionRecord->ExceptionInformation[2],
				PreviousMode,
				ContextRecord,
				TrapFrame,
				ExceptionFrame, CpuContext);
			Handled = TRUE;
			break;

			/* Anything else, do nothing */
		default:

			/* Invalid debug service! Don't handle this! */
			Handled = FALSE;
			break;
		}

		/*
		 * If the PC was not updated, we'll increment it ourselves so execution
		 * continues past the breakpoint.
		 */
		if (ProgramCounter == KeGetContextPc(ContextRecord))
		{
			/* Update it */
			KeSetContextPc(ContextRecord,
				ProgramCounter + KD_BREAKPOINT_SIZE);
		}
	}
	else
	{
		/* Call the worker routine */
		Handled = KdpReport(TrapFrame,
			ExceptionFrame,
			ExceptionRecord,
			ContextRecord,
			PreviousMode,
			SecondChanceException, CpuContext);
	}

	/* Return TRUE or FALSE to caller */
	return Handled;
}


VOID
CommandCommunication(
	IN     UINTN              Vector,
	IN OUT DEBUG_CPU_CONTEXT* CpuContext,
	IN     BOOLEAN            BreakReceived
)
{
	CONTEXT WindbgCtx = { 0 };
	KEXCEPTION_FRAME ExceptionFrameObj = { 0 };
	EXCEPTION_RECORD ExceptionRecordObj = { 0 };
	PEXCEPTION_RECORD ExceptionRecord = &ExceptionRecordObj;
	PKEXCEPTION_FRAME ExceptionFrame = &ExceptionFrameObj;
	PCONTEXT ContextRecord = &WindbgCtx;
	KTRAP_FRAME TrapFrameObj = { 0 };
	PKTRAP_FRAME TrapFrame = &TrapFrameObj;
	UefiCtx2WindbgCtx(CpuContext, &WindbgCtx);
	KPROCESSOR_MODE PreviousMode = KernelMode;
	BOOLEAN SecondChanceException = FALSE;
	//ULONG_PTR ExceptionCommand;

	//RETURN_STATUS                      Status;
	//UINT8                              InputPacketBuffer[DEBUG_DATA_UPPER_LIMIT + sizeof(UINT64) - 1];
	//DEBUG_PACKET_HEADER* DebugHeader;
	//UINT8                              Width;
	/*UINT8                              Data8;
	UINT32                             Data32;
	UINT64                             Data64;*/
	/*DEBUG_DATA_READ_MEMORY* MemoryRead;
	DEBUG_DATA_WRITE_MEMORY* MemoryWrite;*/
	/*DEBUG_DATA_READ_IO* IoRead;
	DEBUG_DATA_WRITE_IO* IoWrite;
	DEBUG_DATA_READ_REGISTER* RegisterRead;
	DEBUG_DATA_WRITE_REGISTER* RegisterWrite;*/
	//UINT8* RegisterBuffer;
	/*DEBUG_DATA_READ_MSR* MsrRegisterRead;
	DEBUG_DATA_WRITE_MSR* MsrRegisterWrite;*/
	//DEBUG_DATA_CPUID* Cpuid;
	UINT8    BreakCause;
	/*DEBUG_DATA_RESPONSE_CPUID          CpuidResponse;
	DEBUG_DATA_SEARCH_SIGNATURE* SearchSignature;
	DEBUG_DATA_RESPONSE_GET_EXCEPTION  Exception;*/
	//DEBUG_DATA_RESPONSE_GET_REVISION   DebugAgentRevision;
	//DEBUG_DATA_SET_VIEWPOINT* SetViewPoint;
	BOOLEAN                            HaltDeferred;
	UINT32                             ProcessorIndex;
	//DEBUG_AGENT_EXCEPTION_BUFFER       AgentExceptionBuffer;
	UINT32                             IssuedViewPoint;
	//DEBUG_AGENT_MAILBOX* Mailbox;
	//UINT8* AlignedDataPtr;

	ProcessorIndex = 0;
	IssuedViewPoint = 0;
	HaltDeferred = BreakReceived;
	ExceptionRecord->ExceptionCode = 0;

	BOOLEAN TimerCommand = FALSE;
	if (MultiProcessorDebugSupport()) {
		ProcessorIndex = GetProcessorIndex();
		SetCpuStopFlagByIndex(ProcessorIndex, TRUE);
		if (mDebugMpContext.ViewPointIndex == ProcessorIndex) {
			//
			// Only the current view processor could set AgentInProgress Flag.
			//
			IssuedViewPoint = ProcessorIndex;
		}
	}

	if (IssuedViewPoint == ProcessorIndex) {
		//
		// Set AgentInProgress Flag.
		//
		SetDebugFlag(DEBUG_AGENT_FLAG_AGENT_IN_PROGRESS, 1);
	}

	/*while (TRUE) {
		if (MultiProcessorDebugSupport()) {
			//
			// Check if the current processor is HOST view point
			//
			if (mDebugMpContext.ViewPointIndex != ProcessorIndex) {
				if (mDebugMpContext.RunCommandSet) {
					//
					// If HOST view point sets RUN flag, run GO command to leave
					//
					SetCpuStopFlagByIndex(ProcessorIndex, FALSE);
					//CommandGo(CpuContext);
					break;
				}
				else {
					//
					// Run into loop again
					//
					CpuPause();
					continue;
				}
			}
		}
	}*/

	STRING Data = { 0 };
	BreakCause = GetBreakCause(Vector, CpuContext);

	switch (BreakCause)
	{
	case DEBUG_DATA_BREAK_CAUSE_UNKNOWN:
	{
		return;
		break;
	}
	case DEBUG_DATA_BREAK_CAUSE_HW_BREAKPOINT:
	{
		CommandSteppingCleanup(CpuContext);
		ExceptionRecord->ExceptionCode = STATUS_BREAKPOINT;
		ExceptionRecord->ExceptionInformation[0] = BREAKPOINT_BREAK;
		break;
	}
	case DEBUG_DATA_BREAK_CAUSE_STEPPING:
	{

		CommandSteppingCleanup(CpuContext);
		ExceptionRecord->ExceptionCode = STATUS_SINGLE_STEP;
		break;
	}
	case DEBUG_DATA_BREAK_CAUSE_SW_BREAKPOINT:
	case DEBUG_DATA_BREAK_CAUSE_EXCEPTION:
	{
		//CommandSteppingCleanup(CpuContext);
		ExceptionRecord->ExceptionCode = STATUS_BREAKPOINT;
		ExceptionRecord->ExceptionInformation[0] = BREAKPOINT_BREAK;
		break;
	}
	case DEBUG_DATA_BREAK_CAUSE_USER_HALT:
	{
		//TimerCommand = TRUE;
		break;
	}
	case DEBUG_DATA_BREAK_CAUSE_IMAGE_LOAD:
	{
		ExceptionRecord->ExceptionCode = STATUS_BREAKPOINT;
		ExceptionRecord->ExceptionInformation[0] = BREAKPOINT_LOAD_SYMBOLS;
		PE_COFF_LOADER_IMAGE_CONTEXT* ImageContext = (PE_COFF_LOADER_IMAGE_CONTEXT*)CpuContext->Dr2;
		UINT64 ImageAddress = (UINT64)ImageContext->ImageAddress;
		UINT64 ImageSize = (UINT64)ImageContext->ImageSize;
		WCHAR* pdbpath = (WCHAR*)ImageContext->PdbPointer;
		UINT32 CheckSum = (UINT32)ImageContext->DebugDirectoryEntryRva;
		PUEFI_SYMBOLS_INFO pSyntheticSymbolInfo = &mSyntheticSymbolInfo[0];
		while (pSyntheticSymbolInfo->SymbolInfo.BaseOfDll != 0)
		{
			pSyntheticSymbolInfo++;
		}

		if (pdbpath)
		{
			//
			if (ForceConsoleOutput)
			{
				KdpDprintf(L"%s\r\n", pdbpath);

			}
			//KdpDprintf(L"DEBUG_DATA_BREAK_CAUSE_IMAGE %s\r\n", pdbpath);
			hvwcscpy(pSyntheticSymbolInfo->SymbolPathBuffer, pdbpath);
		}
		else
		{
			//KdpDprintf(L"DEBUG_DATA_BREAK_CAUSE_IMAGE %a\r\n", ImageAddress);

			hvwcscpy(pSyntheticSymbolInfo->SymbolPathBuffer, L"\\SystemRoot\\system32\\UefiApplication.efi");

			if (ForceConsoleOutput)
			{
				dumpbuf((void*)ImageAddress, 0x100);
			}
		}



		pSyntheticSymbolInfo->SymbolInfo.BaseOfDll = (PVOID)ImageAddress;
		pSyntheticSymbolInfo->SymbolInfo.ProcessId = GetProcessorIndex();
		pSyntheticSymbolInfo->SymbolInfo.SizeOfImage = (ULONG)ImageSize;
		pSyntheticSymbolInfo->SymbolInfo.CheckSum = (ULONG)CheckSum;

		//ForcePorteOutput = TRUE;

		//Data.Length = StrLen(pSyntheticSymbolInfo->SymbolPathBuffer);
		//Data.Length = AsciiStrSize(KdpMessageBuffer);
		Data.Length = (USHORT)w2s(pSyntheticSymbolInfo->SymbolPathBuffer, KdpPathSymbolBuffer);
		//UnicodeStrToAsciiStrS(pSyntheticSymbolInfo->SymbolPathBuffer, KdpPathSymbolBuffer, (Data.Length * 2) + 1);
		UINT64 lenchk = AsciiStrSize(KdpPathSymbolBuffer);
		if (lenchk == 0)
		{
			return;
		}

		Data.Buffer = KdpPathSymbolBuffer;
		Data.MaximumLength = Data.Length;
		ExceptionRecord->ExceptionInformation[1] = (UINT64)&Data;
		ExceptionRecord->ExceptionInformation[2] = (UINT64)&pSyntheticSymbolInfo->SymbolInfo;


		if (CpuContext)
		{
			CpuContext->Dr0 = 0;
			CpuContext->Dr1 = 0;
			CpuContext->Dr2 = 0;
			CpuContext->Dr3 = 0;
			CpuContext->Dr6 = 0;
			CpuContext->Dr7 = 0;
			//CommandSteppingCleanup(CpuContext);
		}
		AsmWriteDr0(0);
		AsmWriteDr1(0);
		AsmWriteDr2(0);
		AsmWriteDr3(0);
		AsmWriteDr6(0);
		AsmWriteDr7(0);
		if (ImageContext)
		{
			FreePool(ImageContext);
		}
		break;
	}
	case DEBUG_DATA_BREAK_CAUSE_IMAGE_UNLOAD:
	{
		ExceptionRecord->ExceptionCode = STATUS_BREAKPOINT;
		ExceptionRecord->ExceptionInformation[0] = BREAKPOINT_UNLOAD_SYMBOLS;
		return;
		break;
	}
	case DEBUG_DATA_BREAK_CAUSE_SYSTEM_RESET:
	{
		return;
		break;
	}
	/*case DEBUG_DATA_BREAK_CAUSE_EXCEPTION:
	{
		return;
		break;
	}*/
	case DEBUG_DATA_BREAK_CAUSE_MEMORY_READY:
	{
		return;
		break;
	}
	default:
	{
		return;
		break;
	}

	}
	/*if (ExceptionRecord->ExceptionCode != 0)
	{
		//KdpDprintf(L"CommandCommunication Vector %d BreakCause %02x\r\n", Vector, BreakCause);
	}
	/* Check if this was a breakpoint due to DbgPrint or Load/UnloadSymbols #1#
	ExceptionCommand = ExceptionRecord->ExceptionInformation[0];
	if ((ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT) &&
		(ExceptionRecord->NumberParameters > 0) &&
		((ExceptionCommand == BREAKPOINT_LOAD_SYMBOLS) ||
			(ExceptionCommand == BREAKPOINT_UNLOAD_SYMBOLS) ||
			(ExceptionCommand == BREAKPOINT_COMMAND_STRING) ||
			(ExceptionCommand == BREAKPOINT_PRINT)))
	{
		/* This we can handle: simply bump the Program Counter #1#
		KeSetContextPc(ContextRecord,
			KeGetContextPc(ContextRecord) + KD_BREAKPOINT_SIZE);
		return;
	}
	else if (KdPitchDebugger)
	{
		/* There's no debugger, fail. #1#
		return;
	}
	/*else if ((KdAutoEnableOnEvent) &&
		(KdPreviouslyEnabled) &&
		!(KdDebuggerEnabled) &&
		(NT_SUCCESS(KdEnableDebugger())) &&
		(KdDebuggerEnabled))#1#
	else*/
	if (TimerCommand)
	{
		return;
		/*KdpReportTimerStateChange(ExceptionRecord, ContextRecord, SecondChanceException, CpuContext);
	   return;*/


	}
	else if (KdDebuggerEnabled)
	{
		/* Debugging was Auto-Enabled. We can now send this to KD. */
		KdpTrap(TrapFrame,
			ExceptionFrame,
			ExceptionRecord,
			ContextRecord,
			PreviousMode,
			SecondChanceException, CpuContext);
		return;
	}
	else
	{
		/* FIXME: All we can do in this case is trace this exception */
		return;
	}


}


void
EFIAPI  WindbgTearDown()
{
	KdpDprintf(L"WindbgTearDown \r\n");
	return;
}


void
EFIAPI  InterruptProcessExit()
{
	KdpDprintf(L"InterruptProcessExit \r\n");
	return;
}

void DumpRspFunction(UINT64 rspval)
{
	for (UINT64 rspnow = rspval; rspnow > rspval - 0x1000; rspnow -= 8)
	{
		UINT64 funcaddr = *(UINT64*)rspnow;
		if (funcaddr > (UINT64)mSyntheticSymbolInfo[0].SymbolInfo.BaseOfDll && funcaddr < (UINT64)mSyntheticSymbolInfo[0].SymbolInfo.BaseOfDll + mSyntheticSymbolInfo[0].SymbolInfo.SizeOfImage)
		{
			Print(L"%p\r\n", funcaddr);
		}
	}
	Print(L"BaseOfDll:=> %p\r\n", mSyntheticSymbolInfo[0].SymbolInfo.BaseOfDll);
	return;

}


void DumpHexFunction(UINT64 funcval)
{
	Print(L"%p\r\n", funcval);
	Print(L"BaseOfDll:=> %p\r\n", mSyntheticSymbolInfo[0].SymbolInfo.BaseOfDll);
	return;

}

void NTAPI HvVmbusTimer();
void*
EFIAPI
InterruptProcess(
	IN UINT32             Vector,
	IN DEBUG_CPU_CONTEXT* CpuContext
)
{
	UINTN                         SavedEip = 0;
	BOOLEAN                       BreakReceived = FALSE;
	DEBUG_CPU_CONTEXT* CpuContextSave = CpuContext;
	if (MultiProcessorDebugSupport()) {
		//
		// If RUN command is executing, wait for it done.
		//
		while (mDebugMpContext.RunCommandSet) {
			CpuPause();
		}
	}
	if (CpuContext->Sig1 != 0x8728367956867960 && CpuContext->Sig0 != 0x5686796087283679)
	{
		KdpDprintf(L"sig %p %p \r\n", CpuContext->Sig0, CpuContext->Sig1);
	}
	UINT8 BreakCause = GetBreakCause(Vector, CpuContext);
	if (Vector != DEBUG_TIMER_VECTOR && Vector != DEBUG_INT3_VECTOR)
	{
		Print(L"InterruptProcess %08x %08x %p %p\r\n", Vector, BreakCause, CpuContext->Eip, mSyntheticSymbolInfo[0].SymbolInfo.BaseOfDll);
		/*//__fastfail(1);
		DumpRspFunction(CpuContext->Rsp);
		KdpDprintf(L"InterruptProcess %08x %08x %p\r\n", Vector, BreakCause, mSyntheticSymbolInfo[0].SymbolInfo.BaseOfDll);
		while (TRUE)
		{
			stall(10);
		}
		return CpuContext;*/
	}
	switch (Vector) {
	case DEBUG_INT1_VECTOR:
	case DEBUG_INT3_VECTOR:
	case DEBUG_EXCEPT_GP_FAULT: {
		switch (BreakCause) {
		case DEBUG_DATA_BREAK_CAUSE_SYSTEM_RESET:

			/*if (AttachHost(BreakCause, READ_PACKET_TIMEOUT, &BreakReceived) != RETURN_SUCCESS) {
				//
				// Try to connect HOST, return if fails
				//
				break;
			}*/

			CommandCommunication(Vector, CpuContext, BreakReceived);
			break;

		case DEBUG_DATA_BREAK_CAUSE_STEPPING:
			//
			// Stepping is finished, send Ack package.


			//
			// Clear Stepping Flag and restore EFLAGS.IF
			//
			CommandSteppingCleanup(CpuContext);
			//SendAckPacket(DEBUG_COMMAND_OK);
			CommandCommunication(Vector, CpuContext, BreakReceived);
			break;

		case DEBUG_DATA_BREAK_CAUSE_MEMORY_READY:
			//
			// Memory is ready
			//
			//SendCommandAndWaitForAckOK(DEBUG_COMMAND_MEMORY_READY, READ_PACKET_TIMEOUT, &BreakReceived, NULL);
			CommandCommunication(Vector, CpuContext, BreakReceived);
			break;

		case DEBUG_DATA_BREAK_CAUSE_IMAGE_LOAD:
		case DEBUG_DATA_BREAK_CAUSE_IMAGE_UNLOAD:
			//
			// Set AL to DEBUG_AGENT_IMAGE_CONTINUE
			//
			/*Al = ArchReadRegisterBuffer(CpuContext, SOFT_DEBUGGER_REGISTER_AX, &Data8);
			*Al = DEBUG_AGENT_IMAGE_CONTINUE;
			*/
		{
			//
			// If HOST is not connected for image load/unload, return
			//


			CommandCommunication(Vector, CpuContext, BreakReceived);
			break;
		}

		//
		// Continue to run the following common code
		//

		case DEBUG_DATA_BREAK_CAUSE_HW_BREAKPOINT:
		case DEBUG_DATA_BREAK_CAUSE_SW_BREAKPOINT:
		case DEBUG_DATA_BREAK_CAUSE_EXCEPTION:
		default:
		{
			if (Vector == DEBUG_INT3_VECTOR) {
				//
				// go back address located "0xCC"
				//
				CpuContext->Eip--;
				SavedEip = CpuContext->Eip;
				CommandCommunication(Vector, CpuContext, BreakReceived);
				if ((SavedEip == CpuContext->Eip) &&
					(*(UINT8*)(UINTN)CpuContext->Eip == DEBUG_SW_BREAKPOINT_SYMBOL))
				{
					//
					// If this is not a software breakpoint set by HOST,
					// restore EIP
					//
					CpuContext->Eip++;
				}
				else if (CpuContext->Eip != SavedEip)
				{
					KdpDprintf(L"rip %p %p \r\n", CpuContext->Eip, SavedEip);

					CpuContext->Eip = SavedEip;
				}
			}
			else {
				CommandCommunication(Vector, CpuContext, BreakReceived);
			}

			break;
		}
		}
		break;
	}
	case DEBUG_TIMER_VECTOR:

	{
		SendApicEoi();

		HvVmbusTimer();
		break;
	}
	default: {
		if (Vector < 20 && BreakCause == DEBUG_DATA_BREAK_CAUSE_EXCEPTION)
		{
			CommandCommunication(Vector, CpuContext, BreakReceived);
		}
		break;
	}
	}


	if (CpuContextSave != CpuContext)
	{
		KdpDprintf(L"ctx %p %p %p %p %p\r\n", CpuContext, CpuContextSave, SavedEip, CpuContext->Eip, CpuContextSave->Eip);
		KdpDprintf(L"handled rip %p %p \r\n", CpuContext->Eip, SavedEip);

	}


	if (CpuContext->Sig1 != 0x8728367956867960 && CpuContext->Sig0 != 0x5686796087283679)
	{
		KdpDprintf(L"sig %p %p \r\n", CpuContext->Sig0, CpuContext->Sig1);
	}
	return CpuContext;
}
/**
  C function called in interrupt handler.

  @param[in] Vector      Vector value of exception or interrupt.
  @param[in] CpuContext  Pointer to save CPU context.

**/
VOID
EFIAPI
InterruptProcess1(
	IN UINT32             Vector,
	IN DEBUG_CPU_CONTEXT* CpuContext
)
{
	UINT8                         InputCharacter;
	UINT8                         BreakCause;

	BOOLEAN                       BreakReceived;
	UINT32                        ProcessorIndex;
	//UINT32                        CurrentDebugTimerInitCount;
	DEBUG_PORT_HANDLE             Handle;
	//UINT8                         Data8;
	//UINT8* Al;
	UINT32                        IssuedViewPoint;
	DEBUG_AGENT_EXCEPTION_BUFFER* ExceptionBuffer;
	UINTN                         buf[0x100];
	UINTN                         SavedEip;
	InputCharacter = 0;
	ProcessorIndex = 0;
	IssuedViewPoint = 0;
	BreakReceived = FALSE;
	//KdpDprintf(L"InterruptProcess %d\r\n", Vector);
	if (mSkipBreakpoint) {
		//
		// If Skip Breakpoint flag is set, means communication is disturbed by hardware SMI, we need to ignore the break points in SMM
		//
		if ((Vector == DEBUG_INT1_VECTOR) || (Vector == DEBUG_INT3_VECTOR)) {
			//DebugPortWriteBuffer(GetDebugPortHandle(), (UINT8*)mWarningMsgIngoreBreakpoint, AsciiStrLen(mWarningMsgIngoreBreakpoint));
			KdpDprintf(L"mWarningMsgIngoreBreakpoint\r\n");
			return;
		}
	}

	if (MultiProcessorDebugSupport()) {
		ProcessorIndex = GetProcessorIndex();
		//
		// If this processor has already halted before, need to check it later
		//
		if (IsCpuStopped(ProcessorIndex)) {
			IssuedViewPoint = ProcessorIndex;
		}
	}

	if ((IssuedViewPoint == ProcessorIndex) && (GetDebugFlag(DEBUG_AGENT_FLAG_STEPPING) != 1) && (GetDebugFlag(DEBUG_AGENT_FLAG_STEPPING) != 0)) {
		//
		// Check if this exception is issued by Debug Agent itself
		// If yes, fill the debug agent exception buffer and LongJump() back to
		// the saved CPU content in CommandCommunication()
		// If exception is issued when executing Stepping, will be handled in
		// exception handle procedure.
		//

		KdpDprintf(L"InterruptProcess DEBUG_AGENT_FLAG_STEPPING\r\n");
		if (GetDebugFlag(DEBUG_AGENT_FLAG_AGENT_IN_PROGRESS) == 1) {
			DebugAgentMsgPrint(
				DEBUG_AGENT_ERROR,
				"Debug agent meet one Exception, ExceptionNum is %d, EIP = 0x%x.\n",
				Vector,
				(UINTN)CpuContext->Eip
			);
			ExceptionBuffer = (DEBUG_AGENT_EXCEPTION_BUFFER*)(UINTN)GetMailboxPointer()->ExceptionBufferPointer;
			ExceptionBuffer->ExceptionContent.ExceptionNum = (UINT8)Vector;
			ExceptionBuffer->ExceptionContent.ExceptionData = (UINT32)CpuContext->ExceptionData;
			LongJump((BASE_LIBRARY_JUMP_BUFFER*)(UINTN)(ExceptionBuffer), 1);
			KdpDprintf(L"InterruptProcess LongJump\r\n");
		}
	}

	if (MultiProcessorDebugSupport()) {
		//
		// If RUN command is executing, wait for it done.
		//
		while (mDebugMpContext.RunCommandSet) {
			CpuPause();
		}
	}

	Handle = GetDebugPortHandle();
	BreakCause = GetBreakCause(Vector, CpuContext);
	switch (Vector) {
	case DEBUG_INT1_VECTOR:
	case DEBUG_INT3_VECTOR:
		switch (BreakCause) {
		case DEBUG_DATA_BREAK_CAUSE_SYSTEM_RESET:

			/*if (AttachHost(BreakCause, READ_PACKET_TIMEOUT, &BreakReceived) != RETURN_SUCCESS) {
				//
				// Try to connect HOST, return if fails
				//
				break;
			}*/

			CommandCommunication(Vector, CpuContext, BreakReceived);
			break;

		case DEBUG_DATA_BREAK_CAUSE_STEPPING:
			//
			// Stepping is finished, send Ack package.
			//
			if (MultiProcessorDebugSupport()) {
				mDebugMpContext.BreakAtCpuIndex = ProcessorIndex;
			}

			//
			// Clear Stepping Flag and restore EFLAGS.IF
			//
			CommandSteppingCleanup(CpuContext);
			//SendAckPacket(DEBUG_COMMAND_OK);
			CommandCommunication(Vector, CpuContext, BreakReceived);
			break;

		case DEBUG_DATA_BREAK_CAUSE_MEMORY_READY:
			//
			// Memory is ready
			//
			//SendCommandAndWaitForAckOK(DEBUG_COMMAND_MEMORY_READY, READ_PACKET_TIMEOUT, &BreakReceived, NULL);
			CommandCommunication(Vector, CpuContext, BreakReceived);
			break;

		case DEBUG_DATA_BREAK_CAUSE_IMAGE_LOAD:
		case DEBUG_DATA_BREAK_CAUSE_IMAGE_UNLOAD:
			//
			// Set AL to DEBUG_AGENT_IMAGE_CONTINUE
			//
			/*Al = ArchReadRegisterBuffer(CpuContext, SOFT_DEBUGGER_REGISTER_AX, &Data8);
			*Al = DEBUG_AGENT_IMAGE_CONTINUE;
			*/
			if (IsHostAttached()) {
				//
				// If HOST is not connected for image load/unload, return
				//


				CommandCommunication(Vector, CpuContext, BreakReceived);
				break;
			}

			//
			// Continue to run the following common code
			//

		case DEBUG_DATA_BREAK_CAUSE_HW_BREAKPOINT:
		case DEBUG_DATA_BREAK_CAUSE_SW_BREAKPOINT:
		default:
			//
			// Send Break packet to HOST
			//

			/*
			 //这个不能锁
			AcquireMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
			ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
			*/
			//
			// Only the first breaking processor could send BREAK_POINT to HOST
			//
			/*if (IsFirstBreakProcessor(ProcessorIndex)) {
				SendBreakPacketToHost(BreakCause, ProcessorIndex, &BreakReceived);
			}*/
			//

			if (Vector == DEBUG_INT3_VECTOR) {
				//
				// go back address located "0xCC"
				//
				CpuContext->Eip--;
				SavedEip = CpuContext->Eip;
				buf[0] = SavedEip;
				CommandCommunication(Vector, CpuContext, BreakReceived);
				if ((SavedEip == CpuContext->Eip) &&
					(*(UINT8*)(UINTN)CpuContext->Eip == DEBUG_SW_BREAKPOINT_SYMBOL))
				{
					//
					// If this is not a software breakpoint set by HOST,
					// restore EIP
					//
					CpuContext->Eip++;
				}
				else if (CpuContext->Eip != SavedEip)
				{
					KdpDprintf(L"unmatch rip %p %p \r\n", CpuContext->Eip, SavedEip);

					CpuContext->Eip = SavedEip;
				}
			}
			else {
				CommandCommunication(Vector, CpuContext, BreakReceived);
			}

			break;
		}

		break;

	case DEBUG_TIMER_VECTOR:

	{
		SendApicEoi();
		break;
		/*AcquireMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
		//KdpDprintf(L"DEBUG_TIMER_VECTOR\r\n");
		if (MultiProcessorDebugSupport()) {
			if (DebugAgentIsBsp(ProcessorIndex)) {
				//
				// If current processor is BSP, check Apic timer's init count if changed,
				// it may be re-written when switching BSP.
				// If it changed, re-initialize debug timer
				//
				CurrentDebugTimerInitCount = GetApicTimerInitCount();
				if (mDebugMpContext.DebugTimerInitCount != CurrentDebugTimerInitCount) {
					InitializeDebugTimer(NULL, FALSE);
					SaveAndSetDebugTimerInterrupt(TRUE);
				}

				CommandCommunication(Vector, CpuContext, FALSE);
			}

			if (!DebugAgentIsBsp(ProcessorIndex) || mDebugMpContext.IpiSentByAp) {
				ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
				//
				// If current processor is not BSP or this is one IPI sent by AP
				//
				if (mDebugMpContext.BreakAtCpuIndex != (UINT32)(-1)) {
					CommandCommunication(Vector, CpuContext, FALSE);
				}

				//
				// Clear EOI before exiting interrupt process routine.
				//
				SendApicEoi();
				break;
			}
			else
			{
				CommandCommunication(Vector, CpuContext, FALSE);
				SendApicEoi();
				ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
				break;
			}
		}
		else
		{
			CommandCommunication(Vector, CpuContext, BreakReceived);
			SendApicEoi();
			ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);

			break;
		}
		break;*/
		/*
		//
		// Only BSP could run here
		//
		while (TRUE) {
			//
			// If there is data in debug port, will check whether it is break(attach/break-in) symbol,
			// If yes, go into communication mode with HOST.
			// If no, exit interrupt process.
			//
			if (DebugReadBreakSymbol(Handle, &InputCharacter) == EFI_NOT_FOUND) {

				if (ForceConsoleOutput)
				{
					DEBUG((DEBUG_INFO, "InterruptProcess DebugReadBreakSymbol EFI_NOT_FOUND\r\n"));
				}
				CommandCommunication(Vector, CpuContext, FALSE);
				break;
			}
			//KdpDprintf(L"InterruptProcess Only BSP could run here\r\n");
			if ((!IsHostAttached() && (InputCharacter == DEBUG_STARTING_SYMBOL_ATTACH)) ||
				(IsHostAttached() && (InputCharacter == DEBUG_COMMAND_HALT)) ||
				(IsHostAttached() && (InputCharacter == DEBUG_COMMAND_GO))
				)
			{
				DebugAgentMsgPrint(DEBUG_AGENT_VERBOSE, "Received data [%02x]\n", InputCharacter);
				//
				// Ack OK for break-in symbol
				//
				//SendAckPacket(DEBUG_COMMAND_OK);

				//
				// If receive GO command in Debug Timer, means HOST may lost ACK packet before.
				//
				if (InputCharacter == DEBUG_COMMAND_GO) {
					break;
				}

				if (!IsHostAttached()) {
					//
					// Try to attach HOST, if no ack received after 200ms, return
					//
					if (AttachHost(BreakCause, READ_PACKET_TIMEOUT, &BreakReceived) != RETURN_SUCCESS) {
						break;
					}
				}

				if (MultiProcessorDebugSupport()) {
					if (FindNextPendingBreakCpu() != -1) {
						SetCpuBreakFlagByIndex(ProcessorIndex, TRUE);
					}
					else {
						HaltOtherProcessors(ProcessorIndex);
					}
				}

				ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
				CommandCommunication(Vector, CpuContext, BreakReceived);
				AcquireMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
				break;
			}
		}

		//
		// Clear EOI before exiting interrupt process routine.
		//
		SendApicEoi();

		ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
		*/



		break;

	}

	default:
		if (Vector <= DEBUG_EXCEPT_SIMD) {
			DebugAgentMsgPrint(
				DEBUG_AGENT_ERROR,
				"Exception happened, ExceptionNum is %d, EIP = 0x%x.\n",
				Vector,
				(UINTN)CpuContext->Eip
			);
			if (BreakCause == DEBUG_DATA_BREAK_CAUSE_STEPPING) {
				//
				// If exception happened when executing Stepping, send Ack package.
				// HOST consider Stepping command was finished.
				//
				if (MultiProcessorDebugSupport()) {
					mDebugMpContext.BreakAtCpuIndex = ProcessorIndex;
				}

				//
				// Clear Stepping flag and restore EFLAGS.IF
				//
				CommandSteppingCleanup(CpuContext);
				//SendAckPacket(DEBUG_COMMAND_OK);
			}
			else {
				//
				// Exception occurs, send Break packet to HOST
				//
				AcquireMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
				//
				// Only the first breaking processor could send BREAK_POINT to HOST
				//
				if (IsFirstBreakProcessor(ProcessorIndex)) {
					SendBreakPacketToHost(BreakCause, ProcessorIndex, &BreakReceived);
				}

				ReleaseMpSpinLock(&mDebugMpContext.DebugPortSpinLock);
			}

			CommandCommunication(Vector, CpuContext, BreakReceived);
		}

		break;
	}

	if (MultiProcessorDebugSupport()) {
		//
		// Clear flag and wait for all processors run here
		//
		SetIpiSentByApFlag(FALSE);
		while (mDebugMpContext.RunCommandSet) {
			CpuPause();
		}

		//
		// Only current (view) processor could clean up AgentInProgress flag.
		//
		if (mDebugMpContext.ViewPointIndex == ProcessorIndex) {
			IssuedViewPoint = mDebugMpContext.ViewPointIndex;
		}
	}

	if ((IssuedViewPoint == ProcessorIndex) && (GetDebugFlag(DEBUG_AGENT_FLAG_STEPPING) != 1)) {
		//
		// If the command is not stepping, clean up AgentInProgress flag
		//
		SetDebugFlag(DEBUG_AGENT_FLAG_AGENT_IN_PROGRESS, 0);
	}

	return;
}


BOOLEAN
EFIAPI
SaveAndSetDebugTimerInterrupt(
	IN BOOLEAN  EnableStatus
);
VOID NTAPI
SetupDebugAgentEnvironmentWindbg(IN EFI_HANDLE        ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable,
	IN DEBUG_AGENT_MAILBOX* Mailbox
);
DEBUG_AGENT_MAILBOX*
GetMailboxFromConfigurationTable(
	VOID
);
VOID
InternalConstructorWorker(
	VOID
);
VOID*
EFIAPI
GetHobList(
	VOID
);

DEBUG_AGENT_MAILBOX*
GetMailboxFromHob(
	IN VOID* HobStart
);



RETURN_STATUS
EFIAPI
DxeDebugAgentLibConstructor(
	IN EFI_HANDLE        ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
);

VOID
EFIAPI
InitializeDebugAgentWindbg(IN EFI_HANDLE        ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable,
	IN UINT32                InitFlag,
	IN VOID* Context  OPTIONAL,
	IN DEBUG_AGENT_CONTINUE  Function  OPTIONAL
)

{
	UINT64* MailboxLocation;
	DEBUG_AGENT_MAILBOX* Mailbox;
	BOOLEAN              InterruptStatus;
	VOID* HobList;
	IA32_DESCRIPTOR      IdtDescriptor;
	IA32_DESCRIPTOR* Ia32Idtr;
	IA32_IDT_ENTRY* Ia32IdtEntry;
	BOOLEAN              PeriodicMode;
	UINTN                TimerCycle;

	if (InitFlag == DEBUG_AGENT_INIT_DXE_AP) {
		//
		// Check if CPU APIC Timer is working, otherwise initialize it.
		//
		KdpDprintf(L"DEBUG_AGENT_INIT_DXE_AP\r\n");
		InitializeLocalApicSoftwareEnable(TRUE);
		GetApicTimerState(NULL, &PeriodicMode, NULL);
		TimerCycle = GetApicTimerInitCount();
		if (!PeriodicMode || (TimerCycle == 0)) {
			InitializeDebugTimer(NULL, FALSE);
		}

		//
		// Invoked by AP, enable interrupt to let AP could receive IPI from other processors
		//
		EnableInterrupts();
		return;
	}

	//
	// Disable Debug Timer interrupt
	//
	SaveAndSetDebugTimerInterrupt(FALSE);
	//
	// Save and disable original interrupt status
	//
	InterruptStatus = SaveAndDisableInterrupts();

	//
	// Try to get mailbox firstly
	//
	HobList = NULL;
	Mailbox = NULL;
	MailboxLocation = NULL;

	switch (InitFlag) {
	case DEBUG_AGENT_INIT_DXE_LOAD:


		//
		// Check if Debug Agent has been initialized before
		//
		if (IsDebugAgentInitialzed()) {
			DEBUG((DEBUG_INFO, "Debug Agent: The former agent will be overwritten by the new one!\n"));
		}
		/*mDxeCoreFlag = TRUE;
		DxeDebugAgentLibConstructor(NULL, NULL);
		mDxeCoreFlag = FALSE;*/








		mMultiProcessorDebugSupport = TRUE;
		//
		// Save original IDT table
		//
		AsmReadIdtr(&IdtDescriptor);
		mSaveIdtTableSize = IdtDescriptor.Limit + 1;
		mSavedIdtTable = AllocateCopyPool(mSaveIdtTableSize, (VOID*)IdtDescriptor.Base);
		//
		// Check if Debug Agent initialized in DXE phase
		//
		Mailbox = GetMailboxFromConfigurationTable();
		if (Mailbox == NULL) {
			//
			// Try to get mailbox from GUIDed HOB build in PEI
			//
			HobList = GetHobList();
			Mailbox = GetMailboxFromHob(HobList);
		}
		if (ForceConsoleOutput)
		{
			DEBUG((DEBUG_INFO, "GetMailboxFromConfigurationTable\r\n"));
		}
		//
		// Set up Debug Agent Environment and try to connect HOST if required
		//
		SetupDebugAgentEnvironmentWindbg(ImageHandle, SystemTable, Mailbox);
		if (ForceConsoleOutput)
		{
			DEBUG((DEBUG_INFO, "SetupDebugAgentEnvironment\r\n"));
		}
		//
		// For DEBUG_AGENT_INIT_S3, needn't to install configuration table and EFI Serial IO protocol
		// For DEBUG_AGENT_INIT_DXE_CORE, InternalConstructorWorker() will invoked in Constructor()
		//
		InternalConstructorWorker();

		if (ForceConsoleOutput)
		{
			DEBUG((DEBUG_INFO, "InternalConstructorWorker\r\n"));
		}
		//
		// Enable Debug Timer interrupt
		//
		SaveAndSetDebugTimerInterrupt(TRUE);
		if (ForceConsoleOutput)
		{
			DEBUG((DEBUG_INFO, "SaveAndSetDebugTimerInterrupt\r\n"));
		}
		// Enable interrupt to receive Debug Timer interrupt
		//
		EnableInterrupts();
		if (ForceConsoleOutput)
		{
			DEBUG((DEBUG_INFO, "EnableInterrupts\r\n"));
		}
		mDebugAgentInitialized = TRUE;

		//FindAndReportModuleImageInfo(SIZE_4KB);

		EnableInterrupts();
		/*__debugbreak();
		__debugbreak();*/
		/*
		if (ForceConsoleOutput)
		{
			DEBUG((DEBUG_INFO, "FindAndReportModuleImageInfo\r\n"));
		}*/
		*(EFI_STATUS*)Context = EFI_SUCCESS;

		if (ForceConsoleOutput)
		{
			DEBUG((DEBUG_INFO, "InitializeDebugAgentWindbg EFI_SUCCESS\r\n"));
		}



		DisableApicTimerInterrupt();
		__debugbreak();
		break;

	case DEBUG_AGENT_INIT_DXE_UNLOAD:
		if (mDebugAgentInitialized) {
			if (IsHostAttached()) {
				*(EFI_STATUS*)Context = EFI_ACCESS_DENIED;
				//
				// Enable Debug Timer interrupt again
				//
				SaveAndSetDebugTimerInterrupt(TRUE);
			}
			else {
				//
				// Restore original IDT table
				//
				AsmReadIdtr(&IdtDescriptor);
				IdtDescriptor.Limit = (UINT16)(mSaveIdtTableSize - 1);
				CopyMem((VOID*)IdtDescriptor.Base, mSavedIdtTable, mSaveIdtTableSize);
				AsmWriteIdtr(&IdtDescriptor);
				FreePool(mSavedIdtTable);
				mDebugAgentInitialized = FALSE;
				*(EFI_STATUS*)Context = EFI_SUCCESS;
			}
		}
		else {
			*(EFI_STATUS*)Context = EFI_NOT_STARTED;
		}
		KdpDprintf(L"DEBUG_AGENT_INIT_DXE_UNLOAD");
		//
		// Restore interrupt state.
		//
		SetInterruptState(InterruptStatus);

		KdExitSystem(ImageHandle);
		break;

	case DEBUG_AGENT_INIT_DXE_CORE:
		KdpDprintf(L"DEBUG_AGENT_INIT_DXE_CORE\r\n");
		mDxeCoreFlag = TRUE;
		mMultiProcessorDebugSupport = TRUE;
		//
		// Try to get mailbox from GUIDed HOB build in PEI
		//
		HobList = Context;
		Mailbox = GetMailboxFromHob(HobList);
		//
		// Set up Debug Agent Environment and try to connect HOST if required
		//
		SetupDebugAgentEnvironmentWindbg(ImageHandle, SystemTable, Mailbox);
		//
		// Enable Debug Timer interrupt
		//
		SaveAndSetDebugTimerInterrupt(TRUE);
		//
		// Enable interrupt to receive Debug Timer interrupt
		//
		EnableInterrupts();

		break;

	case DEBUG_AGENT_INIT_S3:
		KdpDprintf(L"DEBUG_AGENT_INIT_S3\r\n");
		if (Context != NULL) {
			Ia32Idtr = (IA32_DESCRIPTOR*)Context;
			Ia32IdtEntry = (IA32_IDT_ENTRY*)(Ia32Idtr->Base);
			MailboxLocation = (UINT64*)((UINTN)Ia32IdtEntry[DEBUG_MAILBOX_VECTOR].Bits.OffsetLow +
				((UINTN)Ia32IdtEntry[DEBUG_MAILBOX_VECTOR].Bits.OffsetHigh << 16));
			Mailbox = (DEBUG_AGENT_MAILBOX*)(UINTN)(*MailboxLocation);
			VerifyMailboxChecksum(Mailbox);
		}

		//
		// Save Mailbox pointer in global variable
		//
		mMailboxPointer = Mailbox;
		//
		// Set up Debug Agent Environment and try to connect HOST if required
		//
		SetupDebugAgentEnvironmentWindbg(ImageHandle, SystemTable, Mailbox);
		//
		// Disable interrupt
		//
		DisableInterrupts();
		FindAndReportModuleImageInfo(SIZE_4KB);
		if (GetDebugFlag(DEBUG_AGENT_FLAG_BREAK_BOOT_SCRIPT) == 1) {
			//
			// If Boot Script entry break is set, code will be break at here.
			//
			CpuBreakpoint();
		}

		break;

	default:
		//
		// Only DEBUG_AGENT_INIT_PREMEM_SEC and DEBUG_AGENT_INIT_POSTMEM_SEC are allowed for this
		// Debug Agent library instance.
		//
		KdpDprintf(L"DEBUG_AGENT_INIT default\r\n");
		DEBUG((DEBUG_ERROR, "Debug Agent: The InitFlag value is not allowed!\n"));
		CpuDeadLoop();
		break;
	}

	return;
}




