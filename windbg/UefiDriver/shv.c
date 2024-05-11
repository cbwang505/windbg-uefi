/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    shv.c

Abstract:

    This module implements the Driver Entry/Unload for the Simple Hyper Visor.

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#include "shv.h"

VOID
ShvUnload (
    VOID
    )
{
    //
    // Attempt to exit VMX root mode on all logical processors. This will
    // broadcast an interrupt which will execute the callback routine in
    // parallel on the LPs.
    //
    // Note that if SHV is not loaded on any of the LPs, this routine will not
    // perform any work, but will not fail in any way.
    //
    ShvOsRunCallbackOnProcessors(ShvVpUnloadCallback, NULL);

    //
    // Indicate unload
    //
    ShvOsDebugPrint("The SHV has been uninstalled.\n");
}

INT32
ShvLoad (
    VOID
    )
{
    SHV_CALLBACK_CONTEXT callbackContext;

    //
    // Attempt to enter VMX root mode on all logical processors. This will
    // broadcast a DPC interrupt which will execute the callback routine in
    // parallel on the LPs. Send the callback routine the physical address of
    // the PML4 of the system process, which is what this driver entrypoint
    // should be executing in.
    //
    callbackContext.Cr3 = __readcr3();
    callbackContext.FailureStatus = SHV_STATUS_SUCCESS;
    callbackContext.FailedCpu = -1;
    callbackContext.InitCount = 0;
    ShvOsRunCallbackOnProcessors(ShvVpLoadCallback, &callbackContext);

    //
    // Check if all LPs are now hypervised. Return the failure code of at least
    // one of them. 
    //
    // Note that each VP is responsible for freeing its VP data on failure.
    //
    if (callbackContext.InitCount != ShvOsGetActiveProcessorCount())
    {
        ShvOsDebugPrint("The SHV failed to initialize (0x%lX) Failed CPU: %d\n",
                        callbackContext.FailureStatus, callbackContext.FailedCpu);
        return callbackContext.FailureStatus;
    }

    //
    // Indicate success.
    //
    ShvOsDebugPrint("The SHV has been installed.\n");
    return SHV_STATUS_SUCCESS;
}
