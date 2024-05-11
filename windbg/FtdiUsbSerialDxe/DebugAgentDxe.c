/** @file
  Initialize Debug Agent in DXE by invoking Debug Agent Library.

Copyright (c) 2013 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <Guid/EventGroup.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugAgentLib.h>
#include <Library/UefiLib.h>
#include "stdint.h"
#include "utils.h"

EFI_EVENT  mExitBootServiceEvent;
extern  BOOLEAN ForceConsoleOutput;
VOID
EFIAPI
InitializeDebugAgentWindbg(IN EFI_HANDLE        ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable,
	IN UINT32                InitFlag,
	IN VOID* Context, OPTIONAL
	IN DEBUG_AGENT_CONTINUE  Function  OPTIONAL
);
VOID
EFIAPI
InitializeDebugAgentUefi(
	IN UINT32                InitFlag,
	IN VOID* Context  OPTIONAL,
	IN DEBUG_AGENT_CONTINUE  Function  OPTIONAL
);

VOID
NTAPI
KdpDprintf(
	_In_ CHAR16* FormatString,
	...);


/**
  One notified function to disable Debug Timer interrupt when gBS->ExitBootServices() called.

  @param[in]  Event              Pointer to this event
  @param[in]  Context            Event handler private data

**/
VOID
EFIAPI
DisableDebugTimerExitBootService(
	EFI_EVENT  Event,
	VOID* Context
)

{
	Print(L"DisableDebugTimerExitBootService\r\n");
	//SaveAndSetDebugTimerInterrupt(FALSE);
}


//1Ãë
void stall(int multi)
{
	int basecount = 100000* multi;
	gBS->Stall(basecount);
	return;
}

EFI_STATUS
EFIAPI
CoreExitBootServices(
	IN EFI_HANDLE  ImageHandle,
	IN UINTN       MapKey
)
{
	Print(L"fake\r\n");
	return STATUS_SUCCESS;
}
//F:\code\edk2-master\Build\SourceLevelDebugPkg\RELEASE_VS2019\X64\SourceLevelDebugPkg\DebugAgentDxe\DebugAgentDxe\OUTPUT\static_library_files.lst
/**
  The Entry Point for Debug Agent Dxe driver.

  It will invoke Debug Agent Library to enable source debugging feature in DXE phase.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when initialized Debug Agent.

**/
EFI_STATUS
EFIAPI
DebugAgentDxeInitialize(
	IN EFI_HANDLE        ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
)
{
	EFI_STATUS  Status;

	Status = EFI_UNSUPPORTED;

	

	// InitializeDebugAgent (DEBUG_AGENT_INIT_DXE_LOAD, &Status, NULL);
	// InitializeDebugAgentUefi(DEBUG_AGENT_INIT_DXE_LOAD, &Status, NULL);
	InitializeDebugAgentWindbg(ImageHandle, SystemTable,DEBUG_AGENT_INIT_DXE_LOAD, &Status, NULL);
	if (EFI_ERROR(Status)) {
		return Status;
	}

	if (gST->ConOut != NULL) {
		Print(L"Debug Agent: Initialized successfully!\r\n\r\n");
	}
	//ForceConsoleOutput = TRUE;
	//
	// Create event to disable Debug Timer interrupt when exit boot service.
	//
	Status = gBS->CreateEventEx(
		EVT_NOTIFY_SIGNAL,
		TPL_NOTIFY,
		DisableDebugTimerExitBootService,
		NULL,
		&gEfiEventExitBootServicesGuid,
		&mExitBootServiceEvent
	);
	return EFI_SUCCESS;
}

/**
  This is the unload handle for Debug Agent Dxe driver.

  It will invoke Debug Agent Library to disable source debugging feature.

  @param[in]  ImageHandle       The drivers' driver image.

  @retval EFI_SUCCESS           The image is unloaded.
  @retval Others                Failed to unload the image.

**/
EFI_STATUS
EFIAPI
DebugAgentDxeUnload(
	IN EFI_HANDLE  ImageHandle
)
{
	EFI_STATUS  Status;
	Print(L"DebugAgentDxeUnload\r\n");
	Status = EFI_UNSUPPORTED;
	InitializeDebugAgentWindbg(ImageHandle, NULL,DEBUG_AGENT_INIT_DXE_UNLOAD, &Status, NULL);

	if (gST->ConOut != NULL) {
		Print(L"Debug Agent: DebugAgentDxeUnload successfully!\r\n\r\n");
	}
	switch (Status) {
	case EFI_ACCESS_DENIED:
		Print(L"Debug Agent: Host is still connected, please de-attach TARGET firstly!\r\n");
		break;
	case EFI_NOT_STARTED:
		Print(L"Debug Agent: It hasn't been initialized, cannot unload it!\r\n");
		break;
	}

	return Status;
}
