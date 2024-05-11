/*++ NDK Version: 0098

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    rtlfuncs.h

Abstract:

    Function definitions for the Run-Time Library

Author:

    Alex Ionescu (alexi@tinykrnl.org) - Updated - 27-Feb-2006

--*/

#ifndef _RTLFUNCS_H
#define _RTLFUNCS_H



#ifdef __cplusplus
extern "C" {
#endif

	

//
// List Functions
//
FORCEINLINE
VOID
InitializeListHeadUefi(
    _Out_ PLIST_ENTRY_UEFI ListHead
)
{
    ListHead->Flink = ListHead->Blink = ListHead;
    return;
}

FORCEINLINE
VOID
InsertHeadListUefi(
    _Inout_ PLIST_ENTRY_UEFI ListHead,
    _Inout_ PLIST_ENTRY_UEFI Entry
)
{
    PLIST_ENTRY_UEFI OldFlink;
    OldFlink = ListHead->Flink;
    Entry->Flink = OldFlink;
    Entry->Blink = ListHead;
    OldFlink->Blink = Entry;
    ListHead->Flink = Entry;
}

FORCEINLINE
VOID
InsertTailListUefi(
    _Inout_ PLIST_ENTRY_UEFI ListHead,
    _Inout_ PLIST_ENTRY_UEFI Entry
)
{
    PLIST_ENTRY_UEFI OldBlink;
    OldBlink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = OldBlink;
    OldBlink->Flink = Entry;
    ListHead->Blink = Entry;
    return;
}

_Must_inspect_result_
FORCEINLINE
BOOLEAN
IsListEmptyUefi(
    _In_ const PLIST_ENTRY_UEFI ListHead
)
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}


FORCEINLINE
int
ListSizeUefi(
	_In_ const PLIST_ENTRY_UEFI ListHead
)
{
    int idx = 0;
    PLIST_ENTRY_UEFI Entry = ListHead->Flink;
    if (Entry != ListHead)
    {
        idx = 1;
    }
    while (Entry->Flink != ListHead)
    {
        idx++;
        Entry = Entry->Flink;

    }
	return idx;
}



FORCEINLINE
BOOLEAN
RemoveEntryListUefi(
    _In_ PLIST_ENTRY_UEFI Entry)
{
    PLIST_ENTRY_UEFI OldFlink;
    PLIST_ENTRY_UEFI OldBlink;

    OldFlink = Entry->Flink;
    OldBlink = Entry->Blink;
    OldFlink->Blink = OldBlink;
    OldBlink->Flink = OldFlink;
    return (BOOLEAN)(OldFlink == OldBlink);
}

FORCEINLINE
PLIST_ENTRY_UEFI
RemoveHeadListUefi(
    _Inout_ PLIST_ENTRY_UEFI ListHead)
{
    PLIST_ENTRY_UEFI Flink;
    PLIST_ENTRY_UEFI Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

FORCEINLINE
PLIST_ENTRY_UEFI
RemoveTailListUefi(
    _Inout_ PLIST_ENTRY_UEFI ListHead)
{
    PLIST_ENTRY_UEFI Blink;
    PLIST_ENTRY_UEFI Entry;

    Entry = ListHead->Blink;
    Blink = Entry->Blink;
    ListHead->Blink = Blink;
    Blink->Flink = ListHead;
    return Entry;
}


#ifdef __cplusplus
}
#endif

#endif
