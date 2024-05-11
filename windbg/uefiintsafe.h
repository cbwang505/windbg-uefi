/*!
 * \file intsafe.h
 *
 * \brief Windows helper functions for integer overflow prevention
 *
 * \package This file is part of the ReactOS PSDK package.
 *
 * \author
 *   Timo Kreuzer (timo.kreuzer@reactos.org)
 *
 * \copyright THIS SOFTWARE IS NOT COPYRIGHTED
 *
 * This source code is offered for use in the public domain. You may
 * use, modify or distribute it freely.
 *
 * This code is distributed in the hope that it will be useful but
 * WITHOUT ANY WARRANTY. ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 * DISCLAIMED. This includes but is not limited to warranties of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * \todo
 * - missing conversion functions
 * - multiplication functions
 * - signed add, sub and multiply functions
 */
#pragma once

#ifndef _INTSAFE_H_INCLUDED_
#define _INTSAFE_H_INCLUDED_

#include <specstrings.h>

/* Handle ntintsafe here too */

typedef  long NTSTATUS;

typedef wchar_t WCHAR;    // wc,   16-bit UNICODE character

#define  NTAPI  __stdcall
#define DECLSPEC_ALIGN(x) __declspec(align(x))
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_INTEGER_OVERFLOW ((NTSTATUS)0xC0000095)
#define INTSAFE_RESULT NTSTATUS
#define INTSAFE_SUCCESS STATUS_SUCCESS
#define INTSAFE_E_ARITHMETIC_OVERFLOW STATUS_INTEGER_OVERFLOW
#define INTSAFE_NAME(name) Rtl##name
#else // _NTINTSAFE_H_INCLUDED_
#ifndef _HRESULT_DEFINED
typedef _Return_type_success_(return >= 0) long HRESULT;
#endif
#ifndef SUCCEEDED
#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#define FAILED(hr) (((HRESULT)(hr)) < 0)
#define S_OK    ((HRESULT)0L)
#endif
#define INTSAFE_RESULT HRESULT
#define INTSAFE_SUCCESS S_OK
#define INTSAFE_E_ARITHMETIC_OVERFLOW ((HRESULT)0x80070216L)
#define INTSAFE_NAME(name) name
#endif // _NTINTSAFE_H_INCLUDED_


#define FORCEINLINE  __inline 


/* min/max helper macros */

# ifndef min
#  define min(a,b) (((a) < (b)) ? (a) : (b))
# endif
# ifndef max
#  define max(a,b) (((a) > (b)) ? (a) : (b))
# endif


#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif

#ifndef BooleanFlagOn
#define BooleanFlagOn(F,SF)   ((BOOLEAN)(((F) & (SF)) != 0))
#endif

#ifndef SetFlag
#define SetFlag(_F,_SF)       ((_F) |= (_SF))
#endif

#ifndef ClearFlag
#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))
#endif

#if !defined(_W64)
#if defined(_MSC_VER) && !defined(__midl) && (defined(_M_IX86) || defined(_M_ARM))
#define _W64 __w64
#else
#define _W64
#endif
#endif
#define  ANSI_NULL 0
/* Static assert */
#ifndef C_ASSERT
#ifdef _MSC_VER
# define C_ASSERT(e) typedef char __C_ASSERT__[(e)?1:-1]
#else
# define C_ASSERT(e) extern void __C_ASSERT__(int [(e)?1:-1])
#endif
#endif /* C_ASSERT */

/* Computed page size */
#define VSM_PAGE_SIZE  0x1000
#define VSM_PAGE_SIZE_DOUBLE  0x2000

/* Typedefs */
#ifndef _WINNT_
#ifndef _NTDEF_
typedef char CHAR;
typedef unsigned char UCHAR, UINT8;
typedef signed char INT8;
typedef short SHORT;
typedef signed short INT16;
typedef unsigned short USHORT, UINT16;
typedef int INT;
typedef unsigned int UINT32;
typedef signed int INT32;
typedef long LONG;
typedef unsigned long ULONG;
typedef long long LONGLONG, LONG64;
typedef signed long long INT64;
typedef unsigned long long ULONGLONG, DWORDLONG, ULONG64, DWORD64, UINT64;
#ifdef _WIN64
typedef long long INT_PTR, LONG_PTR, SSIZE_T, ptrdiff_t;
typedef unsigned long long UINT_PTR, ULONG_PTR, DWORD_PTR, SIZE_T, size_t;
#else // _WIN64
typedef _W64 int INT_PTR, ptrdiff_t;
typedef _W64 unsigned int UINT_PTR, size_t;
typedef _W64 long LONG_PTR, SSIZE_T;
typedef _W64 unsigned long ULONG_PTR, DWORD_PTR, SIZE_T;
#endif // _WIN64
#endif
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int UINT;
typedef unsigned long DWORD;
#endif // _WINNT_
typedef DWORD* PDWORD;
typedef void* PVOID;
typedef void* LPVOID;
typedef BYTE* PUCHAR;
typedef char* PCHAR;
typedef char* PCSTR;
typedef ULONG* PULONG;
typedef USHORT * PUSHORT;
typedef unsigned __int64 ULONG_PTR, * PULONG_PTR;

typedef BOOLEAN *PBOOLEAN;

typedef struct _STRING
{
	volatile  USHORT Length;
    volatile USHORT MaximumLength;
    volatile PCHAR Buffer;
} STRING, * PSTRING;

typedef struct LIST_ENTRY32 {
	ULONG Flink;
	ULONG Blink;
} LIST_ENTRY32;
typedef LIST_ENTRY32* PLIST_ENTRY32;

typedef struct LIST_ENTRY64 {
	ULONGLONG Flink;
	ULONGLONG Blink;
} LIST_ENTRY64;
typedef LIST_ENTRY64* PLIST_ENTRY64;

/* Singly Linked Lists */
typedef struct _SINGLE_LIST_ENTRY {
	struct _SINGLE_LIST_ENTRY* Next;
} SINGLE_LIST_ENTRY, * PSINGLE_LIST_ENTRY;

typedef struct  _UINT128 {

    UINT64  Low64;
    UINT64  High64;

} UINT128, *PUINT128;

typedef UINT128 M128A;

typedef struct _UINT256 {

    UINT128  Low128;
    UINT128  High128;

} UINT256, *PUINT256;

typedef union _ULARGE_INTEGER {
    
    struct
    {
        DWORD LowPart;
        DWORD HighPart;
    } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;


typedef union _LARGE_INTEGER {
    
    struct
    {
        DWORD LowPart;
        DWORD HighPart;
    } u;
    ULONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;



/* Linked Lists */
typedef struct _LIST_ENTRY_UEFI {
	struct _LIST_ENTRY_UEFI* Flink;
	struct _LIST_ENTRY_UEFI* Blink;
} LIST_ENTRY_UEFI, *PLIST_ENTRY_UEFI;

static int PAGE_SIZE = VSM_PAGE_SIZE;

size_t inline ALIGN_UP(size_t x)
{
	return ((PAGE_SIZE - 1) & x) ? ((x + PAGE_SIZE) & ~(PAGE_SIZE - 1)) : x;
}

size_t inline ALIGN_UP_FIX(size_t x, size_t y)
{
	return ((y - 1) & x) ? ((x + y) & ~(y - 1)) : x;
}