
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


UINT64 signalflag = 0;
UINT64 signalvalue = 0;

__declspec(align(VSM_PAGE_SIZE)) UINT8 synic_message_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 synic_event_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 int_page[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 monitor_pages0[VSM_PAGE_SIZE];
__declspec(align(VSM_PAGE_SIZE)) UINT8 monitor_pages1[VSM_PAGE_SIZE];
//UINT64 synic_message_page = 0;
UINT64 synic_message_page_val = 0;
NTSTATUS HvHvCallPostMessageVtl0(void* buffer, UINT32 buflen);
void dumpbuf(void* buf, int len);
struct vmbus_channel newchannelbuf = { 0 };
struct vmbus_channel* newchannel = &newchannelbuf;
int next_gpadl_handle = 0;
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

void NTAPI ProcessSynicChannel()
{
	return;
}

void ProcessResponseChannel()
{
	struct vmbus_channel_message_header* hdr = (struct vmbus_channel_message_header*)((UINT64)synic_message_page + 0x210);
	if(hdr->msgtype== CHANNELMSG_INVALID)
	{
		return;
	}
	if(hdr->msgtype== CHANNELMSG_OFFERCHANNEL)
	{
		struct vmbus_channel_offer_channel* offer = (struct vmbus_channel_offer_channel*)((UINT64)synic_message_page + 0x210);
		//UINT32 fakeid = *(UINT32*)((UINT64)synic_message_page + 0x210 + 0xb8);
		GUID guid = offer->offer.if_type;
		KdpDprintf(L"vmbus_channel_request_offer_response!msgtype:=>%08x,child_relid:=>%08x\n", offer->header.msgtype, offer->child_relid);
		KdpDprintf(L"if_type:=> %{%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}\n", guid.Data1
			, guid.Data2
			, guid.Data3
			, guid.Data4[0], guid.Data4[1]
			, guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5]
			, guid.Data4[6], guid.Data4[7]);

		guid = offer->offer.if_instance;
		KdpDprintf(L"if_instance:=> %{%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}\n", guid.Data1
			, guid.Data2
			, guid.Data3
			, guid.Data4[0], guid.Data4[1]
			, guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5]
			, guid.Data4[6], guid.Data4[7]);
		/*if(offer->offer.u.pipe.user_def[0]!=0)
		{
			KdpDprintf(L"pipe:=>%a\n", offer->offer.u.pipe.user_def);
		}

		if (offer->offer.u.std.user_def[0] != 0)
		{
			KdpDprintf(L"std:=>%a\n", offer->offer.u.std.user_def);
		}*/
		//dumpbuf(bufmssg, 0x100);
		//offer->child_relid = fakeid;
		hvcopymemory(&newchannel->offermsg, offer,
			sizeof(struct vmbus_channel_offer_channel));
		newchannel->sig_event = VMBUS_EVENT_CONNECTION_ID;
		newchannel->is_dedicated_interrupt =
			(offer->is_dedicated_interrupt != 0);
		newchannel->sig_event = offer->connection_id;
		newchannel->monitor_grp = (u8)offer->monitorid / 32;
		newchannel->monitor_bit = (u8)offer->monitorid % 32;
	}else if(hdr->msgtype == CHANNELMSG_GPADL_CREATED)
	{
		struct vmbus_channel_gpadl_created* resp = (struct vmbus_channel_gpadl_created*)((UINT64)synic_message_page + 0x210);
		KdpDprintf(L"HvVmbusOpen_response!msgtype:=> %08x,child_relid:=> %08x,gpadle:=> %08x,creation_status:=> %08x\n", resp->header.msgtype, resp->child_relid, resp->gpadl, resp->creation_status);
	}
	else if (hdr->msgtype == CHANNELMSG_VERSION_RESPONSE)
	{
		struct vmbus_channel_version_response* resp = ((UINT64)synic_message_page + 0x210);
		KdpDprintf(L"vmbus_channel_version_response!msgtype:=> %08x,version_supported:=> %08x\n", resp->header.msgtype, resp->version_supported);

	}

	return;

}


void ConfigPendingMessageSlot()
{
	PHV_MESSAGE  bufmssg = (PHV_MESSAGE)((UINT64)synic_message_page + 0x200);
	bufmssg->Header.MessageType = 0;
	signalflag = 0;
	
	if (bufmssg->Header.MessageFlags.MessagePending)
	{
		//bufmssg->Header.MessageFlags.MessagePending = 0;
	//	hvresetmemory(synic_message_page, VSM_PAGE_SIZE);

		//auto  eoi
		__writemsr(HvSyntheticMsrEom, 0);

		
	}
	
	return ;

}
BOOLEAN ProcessPendingMessageSlot()
{
	BOOLEAN ret = TRUE;
	int failecount = 0;
	signalflag = 0;
	PHV_MESSAGE  bufmssg = (PHV_MESSAGE)((UINT64)synic_message_page + 0x200);

	while (signalflag == 0)
	{
		failecount++;
		if(failecount>10&& bufmssg->Header.MessageType == 0)
		{
			
			ret = FALSE;
			goto msgeom;
		}else if(bufmssg->Header.MessageType != 0)
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
NTSTATUS HvSYNICVtl0()
{
	NTSTATUS ret = STATUS_SUCCESS;
	
	HV_SYNIC_SIMP SimpVal = { 0 };
	HV_SYNIC_SIEFP SiefpVal = { 0 };
	HV_SYNIC_SCONTROL SControlVal = { 0 };
	SimpVal.AsUINT64 = __readmsr(HvSyntheticMsrSimp);

	KdpDprintf(L"UefiMain!HvSyntheticMsrSimp  regvalue:=> %016llx!\n", SimpVal);

	SiefpVal.AsUINT64 = __readmsr(HvSyntheticMsrSiefp);

	KdpDprintf(L"UefiMain!HvSyntheticMsrSiefp  regvalue:=> %016llx!\n", SiefpVal);
	//synic_message_page=AllocateAlignedPages(1, VSM_PAGE_SIZE);
	SimpVal.BaseSimpGpa = VSM_PAGE_TO_PFN((UINT64)synic_message_page);
	SimpVal.SimpEnabled = 1;
	//synic_message_page = VSM_PFN_TO_PAGE(SimpVal.BaseSimpGpa);
	synic_message_page_val = (UINT64)synic_message_page;
	__writemsr(HvSyntheticMsrSimp, SimpVal.AsUINT64);
	KdpDprintf(L"UefiMain!HvSyntheticMsrSimp  regvalue:=> %016llx, synic_message_page:=> %016llx!\n",
		SimpVal.AsUINT64, synic_message_page);
	SiefpVal.BaseSiefpGpa = VSM_PAGE_TO_PFN((UINT64)synic_event_page);
	SiefpVal.SiefpEnabled = 1;
	__writemsr(HvSyntheticMsrSiefp, SiefpVal.AsUINT64);
	KdpDprintf(L"UefiMain!HvSyntheticMsrSiefp  regvalue:=> %016llx, synic_event_page:=> %016llx!\n",
		SiefpVal.AsUINT64, synic_event_page);
	HV_SYNIC_SINT shared_sint = { 0 };

	shared_sint.AsUINT64 = __readmsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT);
	UINT64 shared_sintorg = shared_sint.AsUINT64;
	shared_sint.Vector = 0x27;
	shared_sint.Masked = FALSE;


	shared_sint.AutoEoi = TRUE;
	__writemsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT, shared_sint.AsUINT64);
	KdpDprintf(L"UefiMain!VMBUS_MESSAGE_SINT shared_sintorg:=> %016llx regvalue:=> %016llx\n",
		shared_sintorg, shared_sint.AsUINT64);
	SControlVal.AsUINT64 = __readmsr(HvSyntheticMsrSControl);
	SControlVal.Enable = 1;
	__writemsr(HvSyntheticMsrSControl, SControlVal.AsUINT64);
	KdpDprintf(L"UefiMain!HvSyntheticMsrSControl  regvalue:=> %016llx!\n", SControlVal.AsUINT64);


	return ret;
}


void HvVmbusNegotiateVersion()
{
	//__writemsr(HvSyntheticMsrEom, 0);
	PHV_MESSAGE  bufmssg = (PHV_MESSAGE)((UINT64)synic_message_page + 0x200);
	
	ConfigPendingMessageSlot();
	struct vmbus_channel_initiate_contact msg = { 0 };
	msg.header.msgtype = CHANNELMSG_INITIATE_CONTACT;
	int vpdix = (int)__readmsr(HV_X64_MSR_VP_INDEX);
	msg.vmbus_version_requested = VERSION_WIN10_V5;
	//msg.interrupt_page = (UINT64)int_page;
	//msg.u.msg_sint = 0x0302;
	msg.u.interrupt_page = 0x0302;
	msg.monitor_page1 = (UINT64)monitor_pages0;
	msg.monitor_page2 = (UINT64)monitor_pages1;
	msg.target_vcpu = vpdix;
	KdpDprintf(L"UefiMain! HvVmbusNegotiateVersion HvHvCallPostMessageVtl0\n");
	HvHvCallPostMessageVtl0(&msg, sizeof(struct vmbus_channel_initiate_contact));

	
	while (ProcessPendingMessageSlot())
	{
		//KdpDprintf(L"UefiMain! ProcessPendingVmbusOpen\n");
	}
	//dumpbuf(bufmssg, 0x100);
	
	return;
}


void HvVmbusRequestOffers()
{
	//
	PHV_MESSAGE  bufmssg = (PHV_MESSAGE)((UINT64)synic_message_page + 0x200);
	ConfigPendingMessageSlot();
	
	struct vmbus_channel_message_header msg = { 0 };
	msg.msgtype = CHANNELMSG_REQUESTOFFERS;
	KdpDprintf(L"UefiMain! HvVmbusRequestOffers HvHvCallPostMessageVtl0\n");
	HvHvCallPostMessageVtl0(&msg, sizeof(struct vmbus_channel_message_header));
	

	while (ProcessPendingMessageSlot())
	{
		//KdpDprintf(L"UefiMain! ProcessPendingVmbusOpen\n");
	}
	return;
}




void HvVmbusOpen()
{
	
	
	ConfigPendingMessageSlot();
    next_gpadl_handle++;
	newchannel->ringbuffer_page = AllocateAlignedPages(2, VSM_PAGE_SIZE);
	newchannel->outbound_page = newchannel->ringbuffer_page;
	newchannel->inbound_page = newchannel->ringbuffer_page + VSM_PAGE_SIZE;
	newchannel->ringbuffer_pagecount = 2;
	newchannel->ringbuffer_send_offset = 1;
	struct vmbus_channel_gpadl_header  gpadlmsg = { 0 };
	gpadlmsg.header.msgtype = CHANNELMSG_GPADL_HEADER;
	//gpadlmsg.child_relid = 0xfff;
	int pagecount = 2;
	gpadlmsg.rangecount = 1;
	gpadlmsg.range_buflen = sizeof(struct gpa_range);
	gpadlmsg.range[0].byte_offset = 0;
	gpadlmsg.range[0].byte_count = pagecount * VSM_PAGE_SIZE;
	gpadlmsg.range[0].pfn_array[0]= VSM_PAGE_TO_PFN((UINT64)newchannel->ringbuffer_page);
	gpadlmsg.range[0].pfn_array[1]= VSM_PAGE_TO_PFN((UINT64)newchannel->ringbuffer_page+ VSM_PAGE_SIZE);

	gpadlmsg.child_relid = newchannel->offermsg.child_relid;
	gpadlmsg.gpadl = next_gpadl_handle;
	//dumpbuf(&gpadlmsg, sizeof(struct vmbus_channel_gpadl_header));
	KdpDprintf(L"UefiMain! HvVmbusOpen HvHvCallPostMessageVtl0 outbound_page:=> %016llx inbound_page:=> %016llx\n", newchannel->outbound_page, newchannel->inbound_page);
	HvHvCallPostMessageVtl0(&gpadlmsg, sizeof(struct vmbus_channel_gpadl_header));
	
	while (ProcessPendingMessageSlot())
	{
		//KdpDprintf(L"UefiMain! ProcessPendingVmbusOpen\n");
	}
	
	return;
	
}