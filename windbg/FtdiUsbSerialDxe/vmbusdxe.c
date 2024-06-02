
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

// 
// Custom Driver Protocol 
// 
#include "../UefiDriver/drvproto.h"
#include "stdint.h"

#include "apic-defs.h"
#include "registers.h"
#include "utils.h"
#include "hvgdk.h"
#include <intrin.h>
#include <rtlfuncs.h>

#define VMBUS_PKT_TRAILER	8

static BOOLEAN SyncFeedBack=FALSE;
extern BOOLEAN VmbusServiceProtocolLoaded;
extern BOOLEAN SintVectorModify;
extern UINT8 vmbus_output_page[];
extern UINT8 vmbus_input_page[];
extern volatile UINT32 vmbus_input_len ;
UINT64 signalflag = 0;
UINT64 signalvalue = 0;
UINT32 gmessageConnectionId = 0;
extern volatile u32 requestid = 1;
volatile u32 feedbackseq = 0;
static u8 vmbus_sint = 5;
//vmbus_sint = VMBUS_MESSAGE_SINT;
//__declspec(align(VSM_PAGE_SIZE)) UINT8 synic_message_page[VSM_PAGE_SIZE];
//__declspec(align(VSM_PAGE_SIZE)) UINT8 synic_event_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 int_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 monitor_pages0[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 monitor_pages1[VSM_PAGE_SIZE];

__declspec(align(VSM_PAGE_SIZE)) UINT8 vmbus_aux_page[VSM_PAGE_SIZE_DOUBLE];

UINT64 synic_message_page = 0;
UINT64 synic_event_page = 0;

NTSTATUS NTAPI HvHvCallPostMessageVtl0(void* buffer, UINT32 buflen);
NTSTATUS NTAPI HvHvSignalEvent(UINT32 evt);
void dumpbuf(void* buf, int len);

int next_gpadl_handle = 0;

GUID  pipeifguid = { 0xa67dfbae,0x7897,0x42ad,{0x9d,0x10,0xd9,0x61,0x56,0xb3,0x69,0x58} };
GUID pipeistguid = { 0x9c7fe450,0x67fc,0x41aa,{0x97,0x32,0x8d,0x4c,0x3e,0xd9,0x3d,0xb4} };


 static u32 magichdr = 0x56867960;
 static u32 magichdrend = 0x87283679;
 static u32 magicreplyhdr = 0x15957899;
 static u32 magicreplyhdrend = 0x36133574;
EFI_EVENT  vmbus_init_event = NULL;
EFI_EVENT  vmbus_negotiate_event = NULL;
EFI_EVENT  vmbus_request_offers_event = NULL;
EFI_EVENT  vmbus_request_open_event = NULL;
EFI_EVENT  vmbus_gpdl_event = NULL;

struct DECLSPEC_ALIGN(8) hv_device {
	u32 nvsp_version;


	u8 rescind;
	u8 tx_disable; /* if true, do not wake up queue again */

	/* Receive buffer allocated by us but manages by NetVSP */
	struct hv_ring_buffer_info recv_buf;


	/* Send buffer allocated by us */
	struct  hv_ring_buffer_info send_buf;

	u32 buf_gpadl_handle;
	u32 sig_event;
	u32 child_relid;
	EFI_EVENT  channel_recv_event;
	u8 channel_recv_signal;
};



typedef struct _KD_CHANNEL_OFFER
{
	LIST_ENTRY_UEFI List;
	struct vmbus_channel_offer_channel offer;
}KD_CHANNEL_OFFER, * PKD_CHANNEL_OFFER;

PKD_CHANNEL_OFFER pPengdingofferchannel;
struct hv_device gpipedev = { 0 };
UINT32 nowgpadl = 0;
KDP_STATUS
NTAPI
CopyRingBuferrMemoryInput(
	OUT UINT8* Buffer,
	IN  UINT32   NumberOfBytes, IN  UINT32   WaiteSeq);


void NTAPI InitGlobalHv();
int hv_ringbuffer_read(struct hv_device* pdev,
	void* buffer, u32 buflen, u32* buffer_actual_len,
	u64* requestid, BOOLEAN raw, BOOLEAN signal);

BOOLEAN NTAPI ProcessResponseChannel()
{
	BOOLEAN ret = FALSE;
	BOOLEAN vmbus_channel_request_offer_response_show = FALSE;
	struct vmbus_channel_message_header* hdr = (struct vmbus_channel_message_header*)(((PHV_MESSAGE)synic_message_page + vmbus_sint)->Payload);
	if (hdr->msgtype == CHANNELMSG_INVALID)
	{
		ret= FALSE;
	}
	if (hdr->msgtype == CHANNELMSG_OPENCHANNEL_RESULT)
	{
		struct vmbus_channel_open_result* result = (struct vmbus_channel_open_result*)(hdr);
		KdpDprintf(L"vmbus_channel_open_result!msgtype:=> %08x,child_relid:=> %08x,openid:=> %08x,status:=> %08x\r\n", result->header.msgtype, result->child_relid, result->openid, result->status);
		if (vmbus_request_open_event)
		{
			gBS->SignalEvent(vmbus_request_open_event);
		}
		ret = TRUE;
	}
	else if (hdr->msgtype == CHANNELMSG_OFFERCHANNEL)
	{
		struct vmbus_channel_offer_channel* offer = (struct vmbus_channel_offer_channel*)(hdr);
		//UINT32 fakeid = *(UINT32*)((UINT64)synic_message_page + 0x210 + 0xb8);
		
		PKD_CHANNEL_OFFER offerchannel = AllocateZeroPool(sizeof(KD_CHANNEL_OFFER));
		hvcopymemory(&offerchannel->offer, offer, sizeof(struct vmbus_channel_offer_channel));
		InsertTailListUefi(&pPengdingofferchannel->List, &offerchannel->List);
		if (CompareGuid(&offer->offer.if_type, &pipeifguid) == TRUE)
		{
			
			if (vmbus_request_offers_event)
			{
				gBS->SignalEvent(vmbus_request_offers_event);			
				
			}
			vmbus_channel_request_offer_response_show = TRUE;
		}
		if (vmbus_channel_request_offer_response_show)
		{
			GUID guid = offer->offer.if_type;
			KdpDprintf(L"vmbus_channel_request_offer_response!msgtype:=>%08x,child_relid:=>%08x\r\n", offer->header.msgtype, offer->child_relid);
			KdpDprintf(L"if_type:=> %{%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}\n", guid.Data1
				, guid.Data2
				, guid.Data3
				, guid.Data4[0], guid.Data4[1]
				, guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5]
				, guid.Data4[6], guid.Data4[7]);

			guid = offer->offer.if_instance;
			KdpDprintf(L"if_instance:=> %{%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}\r\n", guid.Data1
				, guid.Data2
				, guid.Data3
				, guid.Data4[0], guid.Data4[1]
				, guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5]
				, guid.Data4[6], guid.Data4[7]);

		}
		ret = TRUE;
	}
	else if (hdr->msgtype == CHANNELMSG_GPADL_CREATED)
	{
		struct vmbus_channel_gpadl_created* resp = (struct vmbus_channel_gpadl_created*)(hdr);
		KdpDprintf(L"HvVmbusOpen_response!msgtype:=> %08x,child_relid:=> %08x,gpadle:=> %08x,creation_status:=> %08x\r\n", resp->header.msgtype, resp->child_relid, resp->gpadl, resp->creation_status);
		nowgpadl = resp->gpadl;

		if (vmbus_gpdl_event)
		{
			gBS->SignalEvent(vmbus_gpdl_event);
		}
		ret = TRUE;
	}
	else if (hdr->msgtype == CHANNELMSG_VERSION_RESPONSE)
	{
		struct vmbus_channel_version_response* resp = (struct vmbus_channel_version_response*)(hdr);
		KdpDprintf(L"vmbus_channel_version_response!msgtype:=> %08x,version_supported:=> %08x,messageConnectionId:=> %08x\r\n", resp->header.msgtype, resp->version_supported, resp->messageConnectionId);
		gmessageConnectionId = resp->messageConnectionId;
		if (vmbus_negotiate_event)
		{
			gBS->SignalEvent(vmbus_negotiate_event);

		}
		ret = TRUE;
	}
	hdr->msgtype = 0;
	return ret;

}


void NTAPI ProcessSynicChannel()
{/*
	u8 buf[0x100] = { 0 };
	u64 requestid = 1;
	u32 buffer_actual_len = 0;*/
	if (synic_event_page)
	{
		if (gpipedev.child_relid)
		{
			PHV_SYNIC_EVENT_FLAGS  synic_event_page_sint = (PHV_SYNIC_EVENT_FLAGS)synic_event_page + vmbus_sint;

			if (_bittest64((__int64 const*)synic_event_page_sint, gpipedev.child_relid))
			{
				//hv_ringbuffer_read(&gpipedev, (void*)buf, 0x100, &buffer_actual_len, &requestid, TRUE, FALSE);
				gpipedev.channel_recv_signal = 1;
			}
		}
	}
	return;
}
VOID
EFIAPI
SendApicEoi(
	VOID
);
void  NTAPI ConfigPendingMessageSlot()
{
	PHV_MESSAGE  bufmssg = (PHV_MESSAGE)synic_message_page+vmbus_sint;
	bufmssg->Header.MessageType = 0;
	signalflag = 0;

	if (bufmssg->Header.MessageFlags.MessagePending)
	{
		//bufmssg->Header.MessageFlags.MessagePending = 0;
	//	hvresetmemory(synic_message_page, VSM_PAGE_SIZE);

		//auto  eoi
		__writemsr(HvSyntheticMsrEom, 0);
		//

	}
	//SendApicEoi();
	return;

}
BOOLEAN NTAPI ProcessPendingMessageSlot()
{
	BOOLEAN ret = TRUE;
	int failecount = 0;
	signalflag = 0;
	PHV_MESSAGE  bufmssg = (PHV_MESSAGE)synic_message_page+vmbus_sint;

	while (signalflag == 0)
	{
		failecount++;
		if (failecount > 10 && bufmssg->Header.MessageType == 0)
		{

			ret = FALSE;
			goto msgeom;
		}
		else if (bufmssg->Header.MessageType != 0)
		{
			break;
		}
		stall(10);
	}

	/*//
	//KdpDprintf(L"UefiMain!signalvalue:=> %016llx \n", signalvalue);
	*/
	while (bufmssg->Header.MessageType == 0)
	{
		failecount++;
		if (failecount > 10)
		{
			ret = FALSE;
			goto msgeom;
		}
		stall(10);
	}
	ProcessResponseChannel();
msgeom:
	ConfigPendingMessageSlot();

	return ret;
}


UINT64 NTAPI HvVmbusSintVector()
{
	HV_SYNIC_SINT shared_sint = { 0 };
	shared_sint.AsUINT64 = __readmsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT);

	return shared_sint.Vector ;
}


NTSTATUS NTAPI HvSYNICVtl0()
{
	NTSTATUS ret = STATUS_SUCCESS;
	InitGlobalHv();
	HV_SYNIC_SIMP SimpVal = { 0 };
	HV_SYNIC_SIEFP SiefpVal = { 0 };
	HV_SYNIC_SCONTROL SControlVal = { 0 };

	HV_SYNIC_SINT shared_sint = { 0 };

	//vmbus_sint = VMBUS_MESSAGE_SINT;


	SimpVal.AsUINT64 = __readmsr(HvSyntheticMsrSimp);

	KdpDprintf(L"UefiMain!HvSyntheticMsrSimp  regvalue:=> %016llx!\n", SimpVal.AsUINT64);

	SiefpVal.AsUINT64 = __readmsr(HvSyntheticMsrSiefp);

	KdpDprintf(L"UefiMain!HvSyntheticMsrSiefp  regvalue:=> %016llx!\n", SiefpVal.AsUINT64);

	shared_sint.AsUINT64 = __readmsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT);

	KdpDprintf(L"UefiMain!VMBUS_MESSAGE_SINT regvalue:=> %016llx!\n", shared_sint.AsUINT64);

	SControlVal.AsUINT64 = __readmsr(HvSyntheticMsrSControl);

	KdpDprintf(L"UefiMain!HvSyntheticMsrSControl  regvalue:=> %016llx!\n", SControlVal.AsUINT64);

	
	synic_message_page= (UINT64)AllocateAlignedPages(1, VSM_PAGE_SIZE);
	synic_event_page = (UINT64)AllocateAlignedPages(1, VSM_PAGE_SIZE);
	SimpVal.BaseSimpGpa = VSM_PAGE_TO_PFN((UINT64)synic_message_page);
	SimpVal.SimpEnabled = 1;
	//synic_message_page = VSM_PFN_TO_PAGE(SimpVal.BaseSimpGpa);
	//synic_message_page_val = (UINT64)synic_message_page;
	__writemsr(HvSyntheticMsrSimp, SimpVal.AsUINT64);
	KdpDprintf(L"UefiMain!HvSyntheticMsrSimp  regvalue:=> %016llx, synic_message_page:=> %016llx!\n",
		SimpVal.AsUINT64, synic_message_page);
	SiefpVal.BaseSiefpGpa = VSM_PAGE_TO_PFN((UINT64)synic_event_page);
	SiefpVal.SiefpEnabled = 1;
	__writemsr(HvSyntheticMsrSiefp, SiefpVal.AsUINT64);
	KdpDprintf(L"UefiMain!HvSyntheticMsrSiefp  regvalue:=> %016llx, synic_event_page:=> %016llx!\n",
		SiefpVal.AsUINT64, synic_event_page);
	

	
	UINT64 shared_sintorg = shared_sint.AsUINT64;
	shared_sint.Vector = HYPERVISOR_CALLBACK_VECTOR;
	shared_sint.Masked = FALSE;


	shared_sint.AutoEoi = TRUE;
	//__writemsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT, shared_sint.AsUINT64);
	KdpDprintf(L"UefiMain!VMBUS_MESSAGE_SINT shared_sintorg:=> %016llx regvalue:=> %016llx\n",
		shared_sintorg, shared_sint.AsUINT64);
	
	SControlVal.Enable = 1;
	__writemsr(HvSyntheticMsrSControl, SControlVal.AsUINT64);
	KdpDprintf(L"UefiMain!HvSyntheticMsrSControl  regvalue:=> %016llx!\n", SControlVal.AsUINT64);


	return ret;
}

UINT64 NTAPI HvVmbusSintVectorRestore(UINT64 newVector)
{
	HV_SYNIC_SINT shared_sint = { 0 };

	shared_sint.AsUINT64 = __readmsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT);
	UINT64 shared_sintorg = shared_sint.AsUINT64;
	shared_sint.Vector = newVector;
	shared_sint.Masked = FALSE;
	shared_sint.AutoEoi = FALSE;
	__writemsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT, shared_sint.AsUINT64);
	KdpDprintf(L"UefiMain!VMBUS_MESSAGE_SINT shared_sintorg:=> %016llx regvalue:=> %016llx\n",
		shared_sintorg, shared_sint.AsUINT64);


	return shared_sint.Vector;
}


NTSTATUS NTAPI HvSYNICVtl0New()
{
	NTSTATUS ret = STATUS_SUCCESS;
	InitGlobalHv();
	HV_SYNIC_SIMP SimpVal = { 0 };
	HV_SYNIC_SIEFP SiefpVal = { 0 };
	HV_SYNIC_SCONTROL SControlVal = { 0 };

	HV_SYNIC_SINT shared_sint = { 0 };

	//vmbus_sint = VMBUS_MESSAGE_SINT;
	
	//vmbus_sint = 3;

	SimpVal.AsUINT64 = __readmsr(HvSyntheticMsrSimp);

	KdpDprintf(L"UefiMain!HvSyntheticMsrSimp  regvalue:=> %016llx!\n", SimpVal.AsUINT64);

	SiefpVal.AsUINT64 = __readmsr(HvSyntheticMsrSiefp);

	KdpDprintf(L"UefiMain!HvSyntheticMsrSiefp  regvalue:=> %016llx!\n", SiefpVal.AsUINT64);

	shared_sint.AsUINT64 = __readmsr(HV_X64_MSR_SINT0 + vmbus_sint);

	KdpDprintf(L"UefiMain!VMBUS_MESSAGE_SINT regvalue:=> %016llx!\n", shared_sint.AsUINT64);

	SControlVal.AsUINT64 = __readmsr(HvSyntheticMsrSControl);

	KdpDprintf(L"UefiMain!HvSyntheticMsrSControl  regvalue:=> %016llx!\n", SControlVal.AsUINT64);


	synic_message_page = (UINT64)VSM_PFN_TO_PAGE(SimpVal.BaseSimpGpa );
	synic_event_page = (UINT64)VSM_PFN_TO_PAGE(SiefpVal.BaseSiefpGpa);
	
	KdpDprintf(L"UefiMain!synic_message_page %p synic_event_page %p !\n", synic_message_page,synic_event_page);

	if (SintVectorModify)
	{
		UINT64 shared_sintorg = shared_sint.AsUINT64;
		shared_sint.Vector = HYPERVISOR_CALLBACK_VECTOR;
		shared_sint.Masked = FALSE;


		shared_sint.AutoEoi = TRUE;
		__writemsr(HV_X64_MSR_SINT0 + vmbus_sint, shared_sint.AsUINT64);
		KdpDprintf(L"UefiMain!VMBUS_MESSAGE_SINT shared_sintorg:=> %016llx regvalue:=> %016llx\n",
			shared_sintorg, shared_sint.AsUINT64);

	}
	return ret;
}


EFI_STATUS NTAPI HvVmbusNegotiateVersion()
{
	UINTN                     EventIndex=0;
	//__writemsr(HvSyntheticMsrEom, 0);
	//PHV_MESSAGE  bufmssg = (PHV_MESSAGE)synic_message_page+vmbus_sint;
	EFI_STATUS Status = gBS->CreateEvent(0, 0, NULL, NULL, &vmbus_negotiate_event);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	ConfigPendingMessageSlot();
	struct vmbus_channel_initiate_contact msg = { 0 };
	msg.header.msgtype = CHANNELMSG_INITIATE_CONTACT;
	int vpdix = (int)__readmsr(HV_X64_MSR_VP_INDEX);
	msg.vmbus_version_requested = VERSION_WIN10_V5;
	//msg.interrupt_page = (UINT64)int_page;
	msg.u.interrupt_page = 0x0300| vmbus_sint;
	msg.monitor_page1 = (UINT64)monitor_pages0;
	msg.monitor_page2 = (UINT64)monitor_pages1;
	msg.target_vcpu = vpdix;
	gmessageConnectionId = VMBUS_MESSAGE_CONNECTION_ID_4;
	KdpDprintf(L"UefiMain! HvVmbusNegotiateVersion HvHvCallPostMessageVtl0\n");
	HvHvCallPostMessageVtl0(&msg, sizeof(struct vmbus_channel_initiate_contact));


	/*while (ProcessPendingMessageSlot())
	{
		//KdpDprintf(L"UefiMain! ProcessPendingVmbusOpen\n");
	}*/
	
	Status = gBS->WaitForEvent(
		1,
		&vmbus_negotiate_event,
		&EventIndex
	);

	if (EFI_ERROR(Status)) {
		return Status;
	}
	Status = gBS->CloseEvent(vmbus_negotiate_event);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	return Status;
}


EFI_STATUS NTAPI HvVmbusRequestOffers()
{
	UINTN                     EventIndex = 0;
	EFI_STATUS Status = gBS->CreateEvent(0, 0, NULL, NULL, &vmbus_request_offers_event);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	//
	//PHV_MESSAGE  bufmssg = (PHV_MESSAGE)synic_message_page+vmbus_sint;
	//ConfigPendingMessageSlot();

	struct vmbus_channel_message_header msg = { 0 };
	msg.msgtype = CHANNELMSG_REQUESTOFFERS;
	KdpDprintf(L"UefiMain! HvVmbusRequestOffers HvHvCallPostMessageVtl0\n");
	HvHvCallPostMessageVtl0(&msg, sizeof(struct vmbus_channel_message_header));
	
	Status = gBS->WaitForEvent(
		1,
		&vmbus_request_offers_event,
		&EventIndex
	);

	
	if (EFI_ERROR(Status)) {
		return Status;
	}


	Status = gBS->CloseEvent(vmbus_request_offers_event);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	/*while (ProcessPendingMessageSlot())
	{
		//KdpDprintf(L"UefiMain! ProcessPendingVmbusOpen\n");
	}*/


	for (PLIST_ENTRY_UEFI nextentry = pPengdingofferchannel->List.Flink; nextentry != (PLIST_ENTRY_UEFI)pPengdingofferchannel; nextentry = nextentry->Flink)
	{
		PKD_CHANNEL_OFFER newchannelentry = (PKD_CHANNEL_OFFER)nextentry;
		//ConfigPendingMessageSlot();	

		if (CompareGuid(&newchannelentry->offer.offer.if_type, &pipeifguid) == TRUE)
		{

			gpipedev.rescind = FALSE;
			gpipedev.sig_event = newchannelentry->offer.connection_id;
			gpipedev.child_relid = newchannelentry->offer.child_relid;
		}
	}
	KdpDprintf(L"UefiMain! HvVmbusRequestOffers Succcess\n");
	return Status;
}




EFI_STATUS NTAPI HvVmbusOpen(UINT64 ringbuffer, UINT32* gpadl_handle)
{
	UINTN                     EventIndex=0;
	EFI_STATUS Status = gBS->CreateEvent(0, 0, NULL, NULL, &vmbus_gpdl_event);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	struct vmbus_channel newchannelbuf = { 0 };
	struct vmbus_channel* newchannel = &newchannelbuf;

	next_gpadl_handle++;
	//newchannel->sig_event = VMBUS_EVENT_CONNECTION_ID;

	newchannel->offermsg.child_relid = gpipedev.child_relid;
	newchannel->ringbuffer_page = ringbuffer;
	newchannel->outbound_page = newchannel->ringbuffer_page;
	newchannel->inbound_page = newchannel->ringbuffer_page + VSM_PAGE_SIZE;
	newchannel->ringbuffer_pagecount = 2;
	newchannel->ringbuffer_send_offset = 1;
	struct vmbus_channel_gpadl_header  gpadlmsg = { 0 };
	gpadlmsg.header.msgtype = CHANNELMSG_GPADL_HEADER;
	//gpadlmsg.child_relid = 0xfff;
	int pagecount = 6;
	gpadlmsg.rangecount = 1;
	gpadlmsg.range_buflen = sizeof(struct gpa_range);
	gpadlmsg.range[0].byte_offset = 0;
	gpadlmsg.range[0].byte_count = pagecount * VSM_PAGE_SIZE;
	gpadlmsg.range[0].pfn_array[0] = VSM_PAGE_TO_PFN((UINT64)newchannel->ringbuffer_page);
	gpadlmsg.range[0].pfn_array[1] = VSM_PAGE_TO_PFN((UINT64)newchannel->ringbuffer_page + VSM_PAGE_SIZE);
	gpadlmsg.range[0].pfn_array[2] = VSM_PAGE_TO_PFN((UINT64)newchannel->ringbuffer_page + VSM_PAGE_SIZE + VSM_PAGE_SIZE);
	gpadlmsg.range[0].pfn_array[3] = VSM_PAGE_TO_PFN((UINT64)newchannel->ringbuffer_page + VSM_PAGE_SIZE + VSM_PAGE_SIZE + VSM_PAGE_SIZE);
	gpadlmsg.range[0].pfn_array[4] = VSM_PAGE_TO_PFN((UINT64)newchannel->ringbuffer_page + VSM_PAGE_SIZE + VSM_PAGE_SIZE + VSM_PAGE_SIZE+ VSM_PAGE_SIZE);
	gpadlmsg.range[0].pfn_array[5] = VSM_PAGE_TO_PFN((UINT64)newchannel->ringbuffer_page + VSM_PAGE_SIZE + VSM_PAGE_SIZE + VSM_PAGE_SIZE + VSM_PAGE_SIZE + VSM_PAGE_SIZE);

	gpadlmsg.child_relid = newchannel->offermsg.child_relid;
	gpadlmsg.gpadl = next_gpadl_handle;
	//dumpbuf(&gpadlmsg, sizeof(struct vmbus_channel_gpadl_header));
	KdpDprintf(L"UefiMain! HvVmbusOpen HvHvCallPostMessageVtl0 outbound_page:=> %016llx inbound_page:=> %016llx\n", newchannel->outbound_page, newchannel->inbound_page);
	HvHvCallPostMessageVtl0(&gpadlmsg, sizeof(struct vmbus_channel_gpadl_header));


	/*while (ProcessPendingMessageSlot())
	{
		//KdpDprintf(L"UefiMain! ProcessPendingVmbusOpen\n");
	}*/


	Status = gBS->WaitForEvent(
		1,
		&vmbus_gpdl_event,
		&EventIndex
	);

	if (EFI_ERROR(Status)) {
		return Status;
	}
	Status = gBS->CloseEvent(vmbus_gpdl_event);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	*gpadl_handle = nowgpadl;
	return Status;

}


EFI_STATUS NTAPI HvChannelOpen(struct hv_device* pdev)
{
	UINTN                     EventIndex=0;
	EFI_STATUS Status = gBS->CreateEvent(0, 0, NULL, NULL, &vmbus_request_open_event);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	struct vmbus_channel_open_channel open_msg = { 0 };
	open_msg.header.msgtype = CHANNELMSG_OPENCHANNEL;
	open_msg.openid = pdev->buf_gpadl_handle;
	open_msg.child_relid = pdev->child_relid;
	open_msg.ringbuffer_gpadlhandle = pdev->buf_gpadl_handle;
	open_msg.downstream_ringbuffer_pageoffset = 3;
	open_msg.target_vp = 0;
	HvHvCallPostMessageVtl0(&open_msg, sizeof(struct vmbus_channel_open_channel));

	Status = gBS->WaitForEvent(
		1,
		&vmbus_request_open_event,
		&EventIndex
	);

	if (EFI_ERROR(Status)) {
		return Status;
	}
	Status = gBS->CloseEvent(vmbus_request_open_event);
	if (EFI_ERROR(Status)) {
		return Status;
	}


	return Status;
}

void NTAPI HvVmbusTimer()
{
	//PHV_MESSAGE  bufmssg = (PHV_MESSAGE)synic_message_page+vmbus_sint;
	if (SintVectorModify)
	{
		if (signalflag == 0)
		{
			return;
		}
	}
	/*if (bufmssg->Header.MessageType == 0)
	{
		ConfigPendingMessageSlot();
		return;
	}*/
	if(!ProcessResponseChannel())
	{
		
	}
	ConfigPendingMessageSlot();

	return;
}


/* Get the size of the ring buffer */
static inline u32
hv_get_ring_buffersize(const struct hv_ring_buffer_info* ring_info)
{
	return ring_info->ring_datasize;
}


static u64 hv_get_ring_buffer(struct hv_ring_buffer_info* ring_info)
{

	return (u64)ring_info->buf;
}

static inline u32 hv_get_bytes_to_write(const struct hv_ring_buffer_info* rbi)
{
	u32 read_loc, write_loc, dsize, write;

	dsize = rbi->ring_datasize;
	read_loc = (rbi->ring_buffer->read_index);
	write_loc = rbi->ring_buffer->write_index;

	write = write_loc >= read_loc ? dsize - (write_loc - read_loc) :
		read_loc - write_loc;
	return write;
}



/* Get the next write location for the specified ring buffer */
static inline u32
hv_get_next_write_location(struct hv_ring_buffer_info* ring_info)
{
	u32 next = ring_info->ring_buffer->write_index;

	return next;
}

static inline u32
hv_get_next_read_location(struct hv_ring_buffer* ring_info)
{
	u32 next = ring_info->read_index;

	return next;
}


/* Set the next write location for the specified ring buffer */
static inline void
hv_set_next_write_location(struct hv_ring_buffer* ring_info,
	u32 next_write_location)
{
	ring_info->write_index = next_write_location;
	return;
}




static inline u64
hv_get_ring_bufferindices(struct hv_ring_buffer* ring_info)
{
	return (u64)ring_info->write_index << 32;
}



/* Set the next write location for the specified ring buffer */
static inline void
hv_set_next_read_location(struct hv_ring_buffer* ring_info,
	u32 next_read_location)
{
	ring_info->read_index = next_read_location;
	return;
}


static u32 hv_copyto_ringbuffer(
	struct  hv_ring_buffer_info* ring_info,
	u32				start_write_offset,
	void* src,
	u32				srclen)
{
	u64 ring_buffer = hv_get_ring_buffer(ring_info);
	u32 ring_buffer_size = hv_get_ring_buffersize(ring_info);
	if (start_write_offset + srclen > ring_buffer_size)
	{
		UINT32 FragSize = ring_buffer_size - start_write_offset;
		hvcopymemory((void*)(ring_buffer + start_write_offset), src, FragSize);
		UINT32 remainlength = start_write_offset + srclen - ring_buffer_size;
		hvcopymemory((void*)(ring_buffer), (void*)((u64)src + FragSize), remainlength);
	}
	else {
		hvcopymemory((void*)(ring_buffer + start_write_offset), src, srclen);
	}
	start_write_offset += srclen;
	if (start_write_offset >= ring_buffer_size)
		start_write_offset -= ring_buffer_size;


	return start_write_offset;
}


static u32 hv_copyfrom_ringbuffer(
	struct hv_ring_buffer_info* ring_info,
	u32				start_read_offset,
	void* src,
	u32				srclen)
{
	u64 ring_buffer = hv_get_ring_buffer(ring_info);
	u32 ring_buffer_size = hv_get_ring_buffersize(ring_info);

	u32 Index = (start_read_offset) % ring_buffer_size;
	if (Index + srclen > ring_buffer_size) {
		UINT32 FragSize = ring_buffer_size - Index;
		hvcopymemory(src, (void*)(ring_buffer + Index), FragSize);
		start_read_offset = srclen - FragSize;
		hvcopymemory((UINT8*)src + FragSize, (void*)ring_buffer, start_read_offset);
	}
	else {

		start_read_offset = Index + srclen;
		hvcopymemory(src, (void*)(ring_buffer + Index), srclen);
	}

	return start_read_offset;

}








/* Write to the ring buffer */
int hv_ringbuffer_write(struct hv_device* pdev,
	const struct kvec* kv_list, u32 kv_count)
{
	u32 i = 0;
	u32 bytes_avail_towrite;
	u32 totalbytes_towrite = 0;

	u32 next_write_location;
	u32 old_write;
	u64 prev_indices = 0;
	int failcount = 0;
	struct hv_ring_buffer_info* outring_info = &pdev->send_buf;

	if (pdev->rescind)
		return -1;

	for (i = 0; i < kv_count; i++)
		totalbytes_towrite += kv_list[i].iov_len;

	totalbytes_towrite += sizeof(u64);
	u32 ring_buffer_size = hv_get_ring_buffersize(outring_info);
	
	if(totalbytes_towrite> ring_buffer_size)
	{
		Print(L"exceed ring_buffer_size %08x\r\n", totalbytes_towrite);
		return 0;
	}
	rewrite:
	bytes_avail_towrite = hv_get_bytes_to_write(outring_info);

	if (totalbytes_towrite > bytes_avail_towrite)
	{
		failcount++;
		if(failcount>3)
		{
			Print(L"exceed bytes_avail_towrite %08x %08x\r\n", totalbytes_towrite, bytes_avail_towrite);
			return 0;
		}
		else
		{
			stall(10);
			goto rewrite;
		}
		//return -1;
	//	
	}

	/* Write to the ring buffer */
	next_write_location = hv_get_next_write_location(outring_info);

	old_write = next_write_location;



	for (i = 0; i < kv_count; i++) {
		next_write_location = hv_copyto_ringbuffer(outring_info,
			next_write_location,
			kv_list[i].iov_base,
			kv_list[i].iov_len);
	}


	/* Set previous packet start */
	prev_indices = hv_get_ring_bufferindices(outring_info->ring_buffer);


	next_write_location = hv_copyto_ringbuffer(outring_info,
		next_write_location,
		&prev_indices,
		sizeof(u64));


	/* Now, update the write location */
	hv_set_next_write_location(outring_info->ring_buffer, next_write_location);



	HvHvSignalEvent(pdev->sig_event);

	if (pdev->rescind)
		return -1;

	return 0;
}

UINT32 verify_checksum_split(UINT8* buf, UINT32 len, UINT8* buffer,
	u32 bufferlen, UINT8* buffernext,
	u32 bufferlennext)
{
	UINT32 checksum = 0;
	
	u32 bufferlenremain = bufferlen;
	u32 bufferlennextremain = bufferlennext;

	for (UINT32 i = 0; i < len; i += 4)
	{
		UINT32 checksumtmp = 0;
		for (UINT32 p = i; p < i + 4; p++)
		{

			if (p < len)
			{
				UINT32 tmp = (UINT32)buf[p];
				UINT32 idx = p - i;
				checksumtmp |= (tmp << (idx * 8));
			}else if(bufferlen>p-len)
			{
				bufferlenremain--;
				UINT32 padstart = p - len;
				UINT32 tmp = (UINT32)buffer[padstart];
				UINT32 idx = p - i;
				checksumtmp |= (tmp << (idx * 8));
			}else if(bufferlennext >p-len)
			{
				bufferlennextremain--;
				UINT32 padstart = p - len;
				UINT32 tmp = (UINT32)buffernext[padstart];
				UINT32 idx = p - i;
				checksumtmp |= (tmp << (idx * 8));
			}

		}

		checksum = checksum ^ checksumtmp;
	}
	if(bufferlenremain)
	{
		u32 bufferlenremainstart = bufferlen - bufferlenremain;
		u32 bufferlennextremainstart = bufferlennext - bufferlennextremain;
		for (UINT32 i = bufferlenremainstart; i < bufferlen; i += 4)
		{
			UINT32 checksumtmp = 0;
			for (UINT32 p = i; p < i + 4; p++)
			{

				if (p < bufferlen)
				{
					UINT32 tmp = (UINT32)buffer[p];
					UINT32 idx = p - i;
					checksumtmp |= (tmp << (idx * 8));
				}				
				else if (bufferlennextremain > p - bufferlen)
				{
					bufferlennextremain--;
					UINT32 padstart = p - bufferlen;
					UINT32 tmp = (UINT32)buffernext[padstart+ bufferlennextremainstart];
					UINT32 idx = p - i;
					checksumtmp |= (tmp << (idx * 8));
				}

			}

			checksum = checksum ^ checksumtmp;
		}

	}
	if (bufferlennextremain)
	{
		u32 bufferlennextremainstart = bufferlennext - bufferlennextremain;
		for (UINT32 i = bufferlennextremainstart; i < bufferlennext; i += 4)
		{
			UINT32 checksumtmp = 0;
			for (UINT32 p = i; p < i + 4; p++)
			{

				if (p < bufferlennext)
				{
					UINT32 tmp = (UINT32)buffernext[p];
					UINT32 idx = p - i;
					checksumtmp |= (tmp << (idx * 8));
				}
				

			}

			checksum = checksum ^ checksumtmp;
		}
	}
	return checksum;
}

UINT32 verify_checksum_hdr(UINT8* buf, UINT32 len)
{
	UINT32 checksum = 0;	

	for (UINT32 i = 0; i < len; i += 4)
	{
		UINT32 checksumtmp = 0;
		for (UINT32 p = i; p < i + 4; p++)
		{

			if (p < len)
			{
				UINT32 tmp = (UINT32)buf[p];
				UINT32 idx = p - i;
				checksumtmp |= (tmp << (idx * 8));
			}
			
		}

		checksum = checksum ^ checksumtmp;
	}

	return checksum;
}

UINT32 vmbus_sendpacket_checksum_hdr(struct vmbuspipe_hdr_input* hdrchk, u32 requestid64)
{

	UINT32 hdrlen = sizeof(struct vmbuspipe_hdr_input);	
	hdrchk->magic = magicreplyhdr;
	hdrchk->magicend = magicreplyhdrend;
	hdrchk->checksum = 0;
	hdrchk->flag = 3;
	hdrchk->seqnum = (u32)requestid64;
	hdrchk->msgsize = 0;
	UINT32 checksum = verify_checksum_hdr((UINT8*)hdrchk, hdrlen);
	hdrchk->checksum = checksum;
	return checksum;
}


UINT32 vmbus_sendpacket_checksum_pack(struct vmbuspipe_hdr_input* hdrchk, u32 requestid64,void* buffer,
	u32 bufferlen, void* buffernext,
	u32 bufferlennext)
{
	
	UINT32 hdrlen = sizeof(struct vmbuspipe_hdr_input);
	UINT32 hdrlen2buf =  bufferlen + bufferlennext;
	hdrchk->magic = magichdr;
	hdrchk->magicend = magichdrend;
	hdrchk->checksum = 0;
	hdrchk->flag = 1;
	hdrchk->seqnum =(u32)requestid64;
	hdrchk->msgsize = hdrlen2buf;
	UINT32 checksum = verify_checksum_split((UINT8*)hdrchk, hdrlen, (UINT8*)buffer, bufferlen, (UINT8*)buffernext, bufferlennext);
	hdrchk->checksum = checksum;
	return checksum;
}

int vmbus_sendpacket(struct hv_device* pdev, void* buffer,
	u32 bufferlen, u32 requestid64,
	u16 flags)
{
	UINT32 hdrlen = sizeof(struct vmbuspipe_hdr_input);
	enum vmbus_packet_type type = VM_PKT_DATA_INBAND;
	struct vmpacket_descriptor desc;
	u32 packetlen = sizeof(struct vmpacket_descriptor) + bufferlen+ hdrlen + sizeof(struct vmbuspipe_hdr);
	u32 packetlen_aligned = (u32)ALIGN_UP_FIX(packetlen, sizeof(u64));
	
	struct kvec bufferlist[5];
	u64 aligned_data = 0;
	UINT32 hdrlenraw = sizeof(struct vmbuspipe_hdr);
	/* Setup the descriptor */
	desc.type = type; /* VmbusPacketTypeDataInBand; */
	desc.flags = flags; /* VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED; */
	/* in 8-bytes granularity */
	desc.offset8 = sizeof(struct vmpacket_descriptor) >> 3;
	desc.len8 = (u16)(packetlen_aligned >> 3);
	desc.trans_id = requestid64;

	struct vmbuspipe_hdr hdr ={0};

	hdr.flags = 1;
	hdr.msgsize = bufferlen+ hdrlen;
	struct vmbuspipe_hdr_input hdrchk = { 0 };
	vmbus_sendpacket_checksum_pack(&hdrchk, requestid64, buffer, bufferlen, NULL, 0);

	bufferlist[0].iov_base = &desc;
	bufferlist[0].iov_len = sizeof(struct vmpacket_descriptor);
	bufferlist[1].iov_base = &hdr;
	bufferlist[1].iov_len = hdrlenraw;

	bufferlist[2].iov_base = &hdrchk;
	bufferlist[2].iov_len = hdrlen;

	bufferlist[3].iov_base = buffer;
	bufferlist[3].iov_len = bufferlen;
	bufferlist[4].iov_base = &aligned_data;
	bufferlist[4].iov_len = (packetlen_aligned - packetlen);

	return hv_ringbuffer_write(pdev, bufferlist, 5);
}



int vmbus_sendpacket_acknowledge(struct hv_device* pdev, u32 requestid32,
	u16 flags)
{
	UINT32 hdrlen = sizeof(struct vmbuspipe_hdr_input);
	enum vmbus_packet_type type = VM_PKT_DATA_INBAND;
	struct vmpacket_descriptor desc;
	u32 packetlen = sizeof(struct vmpacket_descriptor) +  hdrlen + sizeof(struct vmbuspipe_hdr);
	u32 packetlen_aligned = (u32)ALIGN_UP_FIX(packetlen, sizeof(u64));

	struct kvec bufferlist[4];
	u64 aligned_data = 0;
	UINT32 hdrlenraw = sizeof(struct vmbuspipe_hdr);
	/* Setup the descriptor */
	desc.type = type; /* VmbusPacketTypeDataInBand; */
	desc.flags = flags; /* VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED; */
	/* in 8-bytes granularity */
	desc.offset8 = sizeof(struct vmpacket_descriptor) >> 3;
	desc.len8 = (u16)(packetlen_aligned >> 3);
	desc.trans_id = requestid32;

	struct vmbuspipe_hdr hdr = { 0 };

	hdr.flags = 1;
	hdr.msgsize =  hdrlen;
	struct vmbuspipe_hdr_input hdrchk = { 0 };
	vmbus_sendpacket_checksum_hdr(&hdrchk, requestid32);

	bufferlist[0].iov_base = &desc;
	bufferlist[0].iov_len = sizeof(struct vmpacket_descriptor);
	bufferlist[1].iov_base = &hdr;
	bufferlist[1].iov_len = hdrlenraw;

	bufferlist[2].iov_base = &hdrchk;
	bufferlist[2].iov_len = hdrlen;	
	bufferlist[3].iov_base = &aligned_data;
	bufferlist[3].iov_len = (packetlen_aligned - packetlen);

	return hv_ringbuffer_write(pdev, bufferlist,4);
}





int vmbus_sendpacket_split(struct hv_device* pdev, void* buffer,
	u32 bufferlen, void* buffernext,
	u32 bufferlennext, u32 requestid64,
	u16 flags)
{
	UINT32 hdrlen = sizeof(struct vmbuspipe_hdr_input);
	enum vmbus_packet_type type = VM_PKT_DATA_INBAND;
	struct vmpacket_descriptor desc;
	u32 packetlen = sizeof(struct vmpacket_descriptor) + bufferlen + hdrlen+ bufferlennext + sizeof(struct vmbuspipe_hdr);
	u32 packetlen_aligned = (u32)ALIGN_UP_FIX(packetlen, sizeof(u64));

	struct kvec bufferlist[6];
	u64 aligned_data = 0;
	UINT32 hdrlenraw = sizeof(struct vmbuspipe_hdr);
	/* Setup the descriptor */
	desc.type = type; /* VmbusPacketTypeDataInBand; */
	desc.flags = flags; /* VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED; */
	/* in 8-bytes granularity */
	desc.offset8 = sizeof(struct vmpacket_descriptor) >> 3;
	desc.len8 = (u16)(packetlen_aligned >> 3);
	desc.trans_id = requestid64;

	struct vmbuspipe_hdr hdr = { 0 };

	hdr.flags = 1;
	hdr.msgsize = bufferlen + hdrlen+ bufferlennext;
	struct vmbuspipe_hdr_input hdrchk = { 0 };
	vmbus_sendpacket_checksum_pack(&hdrchk, requestid64, buffer, bufferlen, buffernext, bufferlennext);

	bufferlist[0].iov_base = &desc;
	bufferlist[0].iov_len = sizeof(struct vmpacket_descriptor);
	bufferlist[1].iov_base = &hdr;
	bufferlist[1].iov_len = hdrlenraw;

	bufferlist[2].iov_base = &hdrchk;
	bufferlist[2].iov_len = hdrlen;

	bufferlist[3].iov_base = buffer;
	bufferlist[3].iov_len = bufferlen;

	bufferlist[4].iov_base = buffernext;
	bufferlist[4].iov_len = bufferlennext;


	bufferlist[5].iov_base = &aligned_data;
	bufferlist[5].iov_len = (packetlen_aligned - packetlen);

	return hv_ringbuffer_write(pdev, bufferlist, 6);
}
/*
 * Determine number of bytes available in ring buffer after
 * the current iterator (priv_read_index) location.
 *
 * This is similar to hv_get_bytes_to_read but with private
 * read index instead.
 */
static u32 hv_pkt_iter_avail(const struct hv_ring_buffer_info* rbi)
{
	u32 priv_read_loc = rbi->priv_read_index;
	u32 write_loc = (rbi->ring_buffer->write_index);

	if (write_loc >= priv_read_loc)
		return write_loc - priv_read_loc;
	else
		return (rbi->ring_datasize - priv_read_loc) + write_loc;
}

/*
 * Get first vmbus packet from ring buffer after read_index
 *
 * If ring buffer is empty, returns NULL and no other action needed.
 */
struct vmpacket_descriptor* hv_pkt_iter_first(struct hv_ring_buffer_info* rbi, struct vmpacket_descriptor* desc)
{

	
	u32 hdrlen = sizeof(struct vmpacket_descriptor);
	if (hv_pkt_iter_avail(rbi) < hdrlen)
		return NULL;


	hv_copyfrom_ringbuffer(rbi,
		rbi->priv_read_index,
		desc,
		hdrlen);
	//desc = (struct vmpacket_descriptor*)(hv_get_ring_buffer(rbi) + rbi->priv_read_index);
	if(rbi->priv_read_index+ hdrlen> rbi->ring_datasize)
	{
		//Print(L"exceed vmpacket_descriptor hv_get_ring_buffer partial\r\n");
	}
	return desc;
}



/*
 * Get next vmbus packet from ring buffer.
 *
 * Advances the current location (priv_read_index) and checks for more
 * data. If the end of the ring buffer is reached, then return NULL.
 */
struct vmpacket_descriptor*
	__hv_pkt_iter_next(struct hv_ring_buffer_info* rbi,
		 struct vmpacket_descriptor* desc)
{
	
	u32 packetlen = desc->len8 << 3;
	u32 ring_buffer_size = hv_get_ring_buffersize(rbi);

	/* bump offset to next potential packet */
	rbi->priv_read_index += packetlen + VMBUS_PKT_TRAILER;
	if (rbi->priv_read_index >= ring_buffer_size)
		rbi->priv_read_index -= ring_buffer_size;
	
	/* more data? */
	return hv_pkt_iter_first(rbi, desc);

}

/*
 * Update host ring buffer after iterating over packets. If the host has
 * stopped queuing new entries because it found the ring buffer full, and
 * sufficient space is being freed up, signal the host. But be careful to
 * only signal the host when necesary, both for performance reasons and
 * because Hyper-V protects itself by throttling guests that signal
 * inappropriately.
 *
 * Determing when to signal is tricky. There are three key data inputs that
 * must be handled in this order to avoid race conditions:
 *
 * 1. Update the read_index
 * 2. Read the pending_send_sz
 * 3. Read the current write_index
 *
 * Note that the interrupt_mask is not used to determine when to signal.
 * The interrupt_mask is used only on the guest->host ring buffer when
 * sending requests to the host. The host does not use it on the host->
 * guest ring buffer to indicate whether it should be signaled.
 *
 */
void hv_pkt_iter_close(struct hv_device* pdev, struct hv_ring_buffer_info* rbi, BOOLEAN signal)
{

	u32 orig_read_index, read_index, write_index, pending_sz;
	u32 orig_free_space, free_space;

	/*
	 * Make sure all reads are done before updating the read index since
	 * the writer may start writing to the read area once the read index
	 * is updated.
	 */

	orig_read_index = rbi->ring_buffer->read_index;
	rbi->ring_buffer->read_index = rbi->priv_read_index;

	/*
	 * Older versions of Hyper-V (before WS2012 and Win8) do not
	 * implement pending_send_sz and simply poll if the host->guest
	 * ring buffer is full. No signaling is needed or expected.
	 */
	if (!rbi->ring_buffer->feature_bits.feat_pending_send_sz)
		return;

	/*
	 * Issue a full memory barrier before making the signaling decision.
	 * If the reading of pending_send_sz were to be reordered and happen
	 * before we commit the new read_index, a race could occur.  If the
	 * host were to set the pending_send_sz after we have sampled
	 * pending_send_sz, and the ring buffer blocks before we commit the
	 * read index, we could miss signaling the host.  Issue a full
	 * memory barrier to address this.
	 */


	 /*
	  * If the pending_send_sz is zero, then the ring buffer is not
	  * blocked and there is no need to signal. This is by far the
	  * most common case, so exit quickly for best performance.
	  */
	pending_sz = (rbi->ring_buffer->pending_send_sz);
	if (!pending_sz)
		return;

	/*
	 * Since pending_send_sz is non-zero, this ring buffer is probably
	 * blocked on the host, though we don't know for sure because the
	 * host may check the ring buffer at any time. In any case, see
	 * if we're freeing enough space in the ring buffer to warrant
	 * signaling the host. To avoid duplicates, signal the host only if
	 * transitioning from a "not enough free space" state to a "enough
	 * free space" state. For example, it's possible that this function
	 * could run and free up enough space to signal the host, and then
	 * run again and free up additional space before the host has a
	 * chance to clear the pending_send_sz. The 2nd invocation would be
	 * a null transition from "enough free space" to "enough free space",
	 * which doesn't warrant a signal.
	 *
	 * To do this, calculate the amount of free space that was available
	 * before updating the read_index and the amount of free space
	 * available after updating the read_index. Base the calculation
	 * on the current write_index, protected by READ_ONCE() because
	 * the host could be changing the value. rmb() ensures the
	 * value is read after pending_send_sz is read.
	 */

	write_index = (rbi->ring_buffer->write_index);

	/*
	 * If the state was "enough free space" prior to updating
	 * the read_index, then there's no need to signal.
	 */
	orig_free_space = (write_index >= orig_read_index)
		? rbi->ring_datasize - (write_index - orig_read_index)
		: orig_read_index - write_index;
	if (orig_free_space > pending_sz)
		return;

	/*
	 * If still in a "not enough space" situation after updating the
	 * read_index, there's no need to signal. A later invocation of
	 * this routine will free up enough space and signal the host.
	 */
	read_index = rbi->ring_buffer->read_index;
	free_space = (write_index >= read_index)
		? rbi->ring_datasize - (write_index - read_index)
		: read_index - write_index;
	if (free_space <= pending_sz)
		return;

	//++channel->intr_in_full;
	if (signal)
	{
		HvHvSignalEvent(pdev->sig_event);
	}
	return;
}
u32 next_location_get_fixed(struct hv_ring_buffer_info* rbi,u32 next_location)
{
	u32 ring_buffer_size = hv_get_ring_buffersize(rbi);
	u32 Index = (next_location) % ring_buffer_size;
	return Index;
}

int hv_ringbuffer_read(struct hv_device* pdev,
	void* buffer, u32 buflen, u32* buffer_actual_len,
	u64* prequestid, BOOLEAN raw, BOOLEAN signal)
{
	int ret = 0;
	struct vmpacket_descriptor descstatck={0};
	struct vmpacket_descriptor* desc=&descstatck;
	u32 packetlen, offset;
	struct hv_ring_buffer_info* inring_info = &pdev->recv_buf;
	if ((buflen == 0))
		return -1;

	*buffer_actual_len = 0;
	*prequestid = 0;

	/* Make sure there is something to read */
	desc = hv_pkt_iter_first(inring_info, desc);
	if (desc == NULL) {
		/*
		 * No error is set when there is even no header, drivers are
		 * supposed to analyze buffer_actual_len.
		 */
		return ret;
	}

	offset = raw ? 0 : (desc->offset8 << 3);
	packetlen = (desc->len8 << 3) - offset;
	*buffer_actual_len = packetlen;
	*prequestid = desc->trans_id;

	/*if ((packetlen > buflen))
		return -1;*/


	if (packetlen > buflen)
	{
		packetlen = buflen;
	}
	//u32 next_read_location = (u32)((u64)desc + offset - hv_get_ring_buffer(inring_info));

	u32 desc_location = inring_info->priv_read_index;
	u32 next_read_location = desc_location + offset;

	hv_copyfrom_ringbuffer(inring_info,
		next_read_location,
		buffer,
		packetlen);

	/* since ring is double mapped, only one copy is necessary */
     //hvcopymemory(buffer, (void*)((const char*)desc + offset), packetlen);


	/* Advance ring index to next packet descriptor */
	__hv_pkt_iter_next(inring_info, desc);

	/* Notify host of update */
	hv_pkt_iter_close(pdev, inring_info, signal);
	/*if (signal)
	{
		HvHvSignalEvent(pdev->sig_event);
	}*/
	return (int)packetlen;
}
BOOLEAN hv_ringbuffer_peek(struct hv_device* pdev) {
	u32 hdrlen = sizeof(struct vmpacket_descriptor);
	struct hv_ring_buffer_info* rbi = &pdev->recv_buf;
	if (hv_pkt_iter_avail(rbi) < hdrlen)
	{
		return FALSE;

	}else
	{
		return TRUE;
	}
		

}


int vmbus_sendpacket_windbg(UINT32 vmbus_output_start,
	UINT32 vmbus_output_end)
{
	int failcount = 0;
	requestid++;
	int ret = 0;
	void* buffer = vmbus_output_page + vmbus_output_start;
	u32 savereqid = requestid;
resendvmbus:


	if (vmbus_output_end > vmbus_output_start)
	{
		UINT32 bufferlen = vmbus_output_end - vmbus_output_start;
		ret= vmbus_sendpacket(&gpipedev, buffer, bufferlen, savereqid, VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);	//signalflag = 0;	
	}else
	{
		void* buffernext = vmbus_output_page;
		UINT32 bufferlen = VSM_PAGE_SIZE_DOUBLE - vmbus_output_start;
		u32 bufferlennext = vmbus_output_end;
		//Print(L"vmbus_sendpacket_split\r\n");
		if(vmbus_output_end==0)
		{
			Print(L"vmbus_sendpacket_split vmbus_output_end==0\r\n");
		}
		ret = vmbus_sendpacket_split(&gpipedev, buffer, bufferlen, buffernext, bufferlennext, savereqid, VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);	//signalflag = 0;	
	}
	if (SyncFeedBack)
	{
		KDP_STATUS status = CopyRingBuferrMemoryInput(NULL, 0, savereqid);
		if (status == KDP_PACKET_RESEND)
		{

			if (failcount > 3)
			{
				while (TRUE)
				{
					Print(L"vmbus_sendpacket_windbg failed KDP_PACKET_TIMEOUT %08x \r\n", failcount);
					stall(0x1000);
				}
				return 0;
			}
			failcount++;
			goto resendvmbus;
		}
	}
	return ret;
}

UINT32 verify_checksum(UINT8* buf, UINT32 len)
{
	UINT32 checksum = 0;
	for (UINT32 i=0;i<len;i+=4)
	{
		UINT32 checksumtmp = 0;
		for (UINT32 p = i; p < i+4;p++)
		{

			if(p<len)
			{
				UINT8 tmp = buf[p];
				UINT32 idx = p - i;
				checksumtmp|= (tmp << (idx * 8));
			}
			
		}

		checksum = checksum ^ checksumtmp;
	}

	return checksum;
}

int vmbus_receivepacket_windbg_unpack(void* buffer, UINT32 buflen, UINT32 buflennext, UINT32* buffer_actual_len, UINT32* replyreq)
{
	void* bufferrecieve = (void*)vmbus_aux_page;
	UINT32 buflenrecieve = VSM_PAGE_SIZE_DOUBLE;
	UINT32 hdrlenraw = sizeof(struct vmbuspipe_hdr);
	UINT32 hdrlen = sizeof(struct vmbuspipe_hdr_input);
	UINT32 hdrlen2buf = hdrlenraw+ hdrlen + buflen+ buflennext;
	UINT32 buffer_actual_lenrecieve = 0;
	*buffer_actual_len = 0;
	*replyreq = 0;
	if(buflenrecieve> hdrlen2buf)
	{
		buflenrecieve = hdrlen2buf;
	}
	u64 requestidstack = 0;
	int ret=hv_ringbuffer_read(&gpipedev, (void*)bufferrecieve, buflenrecieve, &buffer_actual_lenrecieve, &requestidstack, FALSE, TRUE);
	if(ret==0)
	{
		return ret;
	}
	u32 packetlen_aligned = (u32)ALIGN_UP_FIX(buffer_actual_lenrecieve, 0x10);
	struct vmbuspipe_hdr* hdrraw =  (struct vmbuspipe_hdr*)bufferrecieve;

	struct vmbuspipe_hdr_input* hdrchk = (struct vmbuspipe_hdr_input*)((UINT8*)bufferrecieve+ hdrlenraw);

	if(!((hdrchk->magic== magichdr&& hdrchk->magicend== magichdrend)|| (hdrchk->magic == magicreplyhdr && hdrchk->magicend == magicreplyhdrend && hdrchk->msgsize == 0 && hdrchk->flag == 2)))
	{
		dumpbuf((void*)bufferrecieve, packetlen_aligned);
		Print(L"vmbus_receivepacket_windbg_unpack!magic failed,dbg %08x %08x %08x\r\n", buffer_actual_lenrecieve, gpipedev.recv_buf.ring_buffer->write_index, gpipedev.recv_buf.priv_read_index);
		return ret;
	}

	//回包类型不需要同步hdr
	if(hdrchk->magic == magicreplyhdr && hdrchk->magicend == magicreplyhdrend)
	{
		*buffer_actual_len = 0;
		UINT32 oldchecksum = hdrchk->checksum;

		hdrchk->checksum = 0;


		UINT32 checksum = verify_checksum((UINT8*)hdrchk, hdrchk->msgsize + hdrlen);
		if (oldchecksum != checksum)
		{
			dumpbuf((void*)bufferrecieve, packetlen_aligned);
			Print(L"vmbus_receivepacket_windbg_unpack!checksum failed,replyreq %08x %08x %08x\r\n", buffer_actual_lenrecieve, gpipedev.recv_buf.ring_buffer->write_index, gpipedev.recv_buf.priv_read_index);
			return 0;
		}
		*replyreq = hdrchk->seqnum;
		if(hdrchk->seqnum!=0)
		{

			return  hdrchk->seqnum;
			
		}else
		{
			Print(L"vmbus_receivepacket_windbg_unpack!seqnum failed,replyreq %08x %08x %08x\r\n", buffer_actual_lenrecieve, gpipedev.recv_buf.ring_buffer->write_index, gpipedev.recv_buf.priv_read_index);
		}
	}

	*buffer_actual_len = 0;
	if(hdrchk->msgsize+ hdrlen!= hdrraw->msgsize)
	{
		dumpbuf((void*)bufferrecieve, packetlen_aligned);
		Print(L"vmbus_receivepacket_windbg_unpack!msgsize failed,dbg %08x %08x %08x\r\n", buffer_actual_lenrecieve, gpipedev.recv_buf.ring_buffer->write_index, gpipedev.recv_buf.priv_read_index);
		return ret;
	}
	UINT32 oldchecksum = hdrchk->checksum;

	hdrchk->checksum = 0;


	UINT32 checksum = verify_checksum((UINT8*)hdrchk, hdrchk->msgsize+ hdrlen);
	if(oldchecksum!= checksum)
	{
		dumpbuf((void*)bufferrecieve, packetlen_aligned);
		Print(L"vmbus_receivepacket_windbg_unpack!checksum failed,dbg %08x %08x %08x\r\n", buffer_actual_lenrecieve, gpipedev.recv_buf.ring_buffer->write_index, gpipedev.recv_buf.priv_read_index);
		return 0;
	}
	//KdpDprintf(L"vmbus_receivepacket_windbg_unpack!success  %08x\r\n", hdrchk->msgsize);
	if (hdrchk->msgsize <= buflen)
	{
		hvcopymemory(buffer, (void*)((UINT8*)bufferrecieve + hdrlenraw + hdrlen), hdrchk->msgsize);
		*buffer_actual_len = hdrchk->msgsize;
	}else
	{
		hvcopymemory(buffer, (void*)((UINT8*)bufferrecieve + hdrlenraw + hdrlen), buflen);
		UINT32 remainlen = hdrchk->msgsize - buflen;
		if (remainlen <= buflennext)
		{
			hvcopymemory(vmbus_input_page, (void*)((UINT8*)bufferrecieve + hdrlenraw + hdrlen+ buflen), remainlen);

			*buffer_actual_len = hdrchk->msgsize+ remainlen;
		}else
		{
			hvcopymemory(vmbus_input_page, (void*)((UINT8*)bufferrecieve + hdrlenraw + hdrlen + buflen), buflennext);


			*buffer_actual_len = hdrchk->msgsize + buflennext;
		}

		
	}
	if (SyncFeedBack)
	{
		vmbus_sendpacket_acknowledge(&gpipedev, hdrchk->seqnum, VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
		if (feedbackseq == 0)
		{
			feedbackseq = hdrchk->seqnum;
		}
		else
		{
			u32 feedbackseqchk = feedbackseq + 1;
			if (feedbackseqchk != hdrchk->seqnum)
			{
				Print(L"vmbus_sendpacket_acknowledge!dbg %08x %08x \r\n", feedbackseq, hdrchk->seqnum);
			}

			feedbackseq = hdrchk->seqnum;
		}
	}
	
	return hdrchk->msgsize;
}


BOOLEAN  vmbus_channel_has_data()
{
	return hv_ringbuffer_peek(&gpipedev) == TRUE;
}

int vmbus_receivepacket_windbg(void* buffer, UINT32 buflen,UINT32 buflennext, UINT32* buffer_actual_len, UINT32* replyreq)
{
	volatile PHV_SYNIC_EVENT_FLAGS  synic_event_page_sint = (PHV_SYNIC_EVENT_FLAGS)synic_event_page + vmbus_sint;
	int failcount = 0;
	int ret = 0;
	BOOLEAN hasdata = FALSE;
	BOOLEAN ContinueOnStack = TRUE;
	*replyreq = 0;
	while (failcount < 10)
	{
		if (!_bittestandreset64((__int64*)synic_event_page_sint, gpipedev.child_relid))
		{		
			if (vmbus_channel_has_data() == FALSE)
			{
				stall(10);
				failcount++;
			}
			else
			{
				hasdata = TRUE;
				break;
			}
		}
		else
		{
			if (vmbus_channel_has_data() == FALSE)
			{
				stall(10);
				failcount++;
			}
			else
			{
				hasdata = TRUE;
				break;
			}
		}
	}
	if (hasdata)
	{		
		ret= vmbus_receivepacket_windbg_unpack(buffer, buflen, buflennext,buffer_actual_len, replyreq);
		if (ret > 0)
		{
			vmbus_input_len += *buffer_actual_len;
		}
	}else if(!ContinueOnStack)
	{
		Print(L"vmbus_receivepacket_windbg!_bittestandreset64 failed, %08x\n", failcount);

		while (TRUE)
		{
			stall(0x1000);
		}
	}
	return ret;
}

EFI_STATUS NTAPI HvVmbusServiceDxeInitialize()
{
	
	
	pPengdingofferchannel = (PKD_CHANNEL_OFFER)AllocateZeroPool(sizeof(KD_CHANNEL_OFFER));
	InitializeListHeadUefi(&pPengdingofferchannel->List);
	EFI_STATUS Status = gBS->CreateEvent(0, 0, NULL, NULL, &vmbus_init_event);
	if (EFI_ERROR(Status)) {
		return Status;
	}

	Status = HvVmbusNegotiateVersion();
	if (EFI_ERROR(Status)) {
		return Status;
	}
	
	Status = HvVmbusRequestOffers();
	if (EFI_ERROR(Status)) {
		return Status;
	}



	int pagecount = 6;
	int pagecountsplit = 3;
	int allpagesize = pagecount * VSM_PAGE_SIZE;
	gpipedev.channel_recv_event = 0;
	gpipedev.channel_recv_signal = 0;
	gpipedev.send_buf.bufpage = (UINT64)AllocateAlignedPages(pagecount, VSM_PAGE_SIZE);
	gpipedev.send_buf.ring_buffer = (struct hv_ring_buffer*)gpipedev.send_buf.bufpage;
	gpipedev.send_buf.buf = gpipedev.send_buf.bufpage + VSM_PAGE_SIZE;
	gpipedev.send_buf.buf_size = VSM_PAGE_SIZE * pagecountsplit;
	gpipedev.send_buf.priv_read_index = 0;
	gpipedev.send_buf.ring_buffer->read_index = 0;
	gpipedev.send_buf.ring_buffer->write_index = 0;

	gpipedev.send_buf.ring_datasize = VSM_PAGE_SIZE_DOUBLE;
	gpipedev.recv_buf.bufpage = (UINT64)gpipedev.send_buf.bufpage + (pagecountsplit * VSM_PAGE_SIZE);
	gpipedev.recv_buf.ring_buffer = (struct hv_ring_buffer*)gpipedev.recv_buf.bufpage;
	gpipedev.recv_buf.buf = gpipedev.recv_buf.bufpage + VSM_PAGE_SIZE;
	gpipedev.recv_buf.buf_size = VSM_PAGE_SIZE * pagecountsplit;
	gpipedev.recv_buf.ring_datasize = VSM_PAGE_SIZE_DOUBLE;
	gpipedev.recv_buf.priv_read_index = 0;
	gpipedev.recv_buf.ring_buffer->read_index = 0;
	gpipedev.recv_buf.ring_buffer->write_index = 0;

	hvresetmemory((void*)gpipedev.send_buf.bufpage, allpagesize);


	Status = HvVmbusOpen((UINT64)gpipedev.send_buf.bufpage, &gpipedev.buf_gpadl_handle);
	if (EFI_ERROR(Status)) {
		return Status;
	}	
	Status = HvChannelOpen(&gpipedev);
	if (EFI_ERROR(Status)) {
		return Status;
	}
	VmbusServiceProtocolLoaded = TRUE;
	KdpDprintf(L"Vmbus Channel Service Protocol Loaded , Initializing\r\n");

	return Status;
}

void testsendrecv()
{
	u32 requestidstack = 0;
	u64 requestidstack64 = 0;
	PHV_SYNIC_EVENT_FLAGS  synic_event_page_sint = (PHV_SYNIC_EVENT_FLAGS)synic_event_page + vmbus_sint;
	u8 buf[0x100] = { 0 };
	u8 tmp[0x100] = { 1,2,3,4,5,5,7,8 };
	BOOLEAN ForceConsoleOutputStack = FALSE;
	if (ForceConsoleOutputStack)
	{
		struct kvec testkv = { 0 };

		testkv.iov_base = buf;
		testkv.iov_len = 8;


		hvcopymemory(buf, tmp, 8);
		gpipedev.channel_recv_signal = 0;

		//vmbus_sendpacket(&gpipedev, buf, 0x100, requestid, VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
		vmbus_sendpacket(&gpipedev, buf, 0x100, requestidstack, 0);	//signalflag = 0;	
		/*while (gpipedev.channel_recv_signal == 0)
		{
			stall(10);
		}*/


		if (!_bittestandreset64((__int64*)synic_event_page_sint, gpipedev.child_relid))
		{
			//hv_ringbuffer_read(&gpipedev, (void*)buf, 0x100, &buffer_actual_len, &requestid, TRUE, FALSE);
			stall(10);
		}
		if (ForceConsoleOutputStack)
		{
			dumpbuf((void*)synic_event_page_sint, 0x10);
		}
		gpipedev.channel_recv_signal = 0;
		UINT32 buffer_actual_len = 0; ;
		while (hv_ringbuffer_peek(&gpipedev) == FALSE)
		{
			stall(10);
		}
		hv_ringbuffer_read(&gpipedev, (void*)buf, 0x100, &buffer_actual_len, &requestidstack64, TRUE, TRUE);
		if (ForceConsoleOutputStack)
		{
			KdpDprintf(L"hv_ringbuffer_read!buffer_actual_len:=> %08x,child_relid:=> %08x\r\n", buffer_actual_len, gpipedev.child_relid);
			dumpbuf((void*)gpipedev.recv_buf.buf, 0x100);
			dumpbuf((void*)synic_event_page_sint, 0x10);
		}

		/*for (int i = 0; i < 0x100; i++)
		{

			buf[i] = (uint8_t)(buf[i] ^ i);
		}*/
		requestidstack++;
		gpipedev.channel_recv_signal = 0;




		vmbus_sendpacket(&gpipedev, buf, 0x100, requestidstack, 0);	//signalflag = 0;

	}
	/*buffer_actual_len = 0;
	dumpbuf((void*)synic_event_page_sint, 0x10);
	if (!_bittestandreset64((__int64 *)synic_event_page_sint, gpipedev.child_relid))
	{
		//hv_ringbuffer_read(&gpipedev, (void*)buf, 0x100, &buffer_actual_len, &requestid, TRUE, FALSE);
		stall(10);
	}

	/*while (gpipedev.channel_recv_signal == 0)
	{
		stall(10);
	}#1#
	while (hv_ringbuffer_peek(&gpipedev) == FALSE)
	{
		stall(10);
	}
	hv_ringbuffer_read(&gpipedev, (void*)buf, 0x100, &buffer_actual_len, &requestid, TRUE, TRUE);
	KdpDprintf(L"hv_ringbuffer_read2!buffer_actual_len:=> %08x,child_relid:=> %08x\r\n", buffer_actual_len, gpipedev.child_relid);
	dumpbuf((void*)buf, 0x100);*/


	if (ForceConsoleOutputStack)
	{
		dumpbuf((void*)synic_event_page_sint, 0x10);
	}
}