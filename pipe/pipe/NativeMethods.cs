using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace pipe
{
    [StructLayout(LayoutKind.Sequential)]
    public struct OFFSET_INFO
    {
        /// DWORD->unsigned int
        public uint Offset;

        /// DWORD->unsigned int
        public uint OffsetHigh;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct DATA_INFO
    {
        /// Anonymous_ac6e4301_4438_458f_96dd_e86faeeca2a6
        [FieldOffset(0)]
        public OFFSET_INFO offsetInfo;

        /// PVOID->void*
        [FieldOffset(0)]
        public IntPtr Pointer;
    }



    [StructLayout(LayoutKind.Sequential)]
    public struct OVERLAPPED
    {
        /// ULONG_PTR->unsigned int
        public uint Internal;

        /// ULONG_PTR->unsigned int
        public uint InternalHigh;

        /// Anonymous_7416d31a_1ce9_4e50_b1e1_0f2ad25c0196
        public DATA_INFO DataInfo;

        /// HANDLE->void*
        public IntPtr hEvent;
    }
    public class Kernel32
    {
        
        /// Return Type: void
        ///dwErrorCode: DWORD->unsigned int
        ///dwNumberOfBytesTransfered: DWORD->unsigned int
        ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
        public delegate void LPOVERLAPPED_COMPLETION_ROUTINE(uint dwErrorCode, uint dwNumberOfBytesTransfered, ref OVERLAPPED lpOverlapped);


        /// Return Type: BOOL->int
        ///hFile: HANDLE->void*
        ///lpBuffer: LPCVOID->void*
        ///nNumberOfBytesToWrite: DWORD->unsigned int
        ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
        ///lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE
        [DllImport("kernel32.dll", EntryPoint = "WriteFileEx", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteFileEx(
            [In] IntPtr hFile, [In] IntPtr lpBuffer, uint nNumberOfBytesToWrite, ref OVERLAPPED lpOverlapped,
            LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);


        /// Return Type: BOOL->int
        ///hFile: HANDLE->void*
        ///lpBuffer: LPCVOID->void*
        ///nNumberOfBytesToWrite: DWORD->unsigned int
        ///lpNumberOfBytesWritten: LPDWORD->DWORD*
        ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
        [DllImport("kernel32.dll", EntryPoint = "WriteFile", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteFile(
            [In] IntPtr hFile, [In] IntPtr lpBuffer, uint nNumberOfBytesToWrite, ref uint lpNumberOfBytesWritten, IntPtr lpOverlapped);


        /// Return Type: BOOL->int
        ///hFile: HANDLE->void*
        ///lpBuffer: LPVOID->void*
        ///nNumberOfBytesToRead: DWORD->unsigned int
        ///lpNumberOfBytesRead: LPDWORD->DWORD*
        ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
        [DllImport("kernel32.dll", EntryPoint = "ReadFile", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadFile([In] IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, ref uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        /// Return Type: BOOL->int
        ///hFile: HANDLE->void*
        ///lpBuffer: LPVOID->void*
        ///nNumberOfBytesToRead: DWORD->unsigned int
        ///lpOverlapped: LPOVERLAPPED->_OVERLAPPED*
        ///lpCompletionRoutine: LPOVERLAPPED_COMPLETION_ROUTINE
        [DllImport("kernel32.dll", EntryPoint = "ReadFileEx", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadFileEx(
            [In] IntPtr hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, ref OVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);


        [DllImport("kernel32.dll", EntryPoint = "SleepEx", SetLastError = true)]
        public static extern uint SleepEx(uint dwMilliseconds, bool bAlertable);

    }

    public class Vmbuspiper
    {
        [DllImport("vmbuspiper.dll", EntryPoint = "VmbusPipeServerConnectPipe")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern
            bool  VmbusPipeServerConnectPipe(
                [In] IntPtr PipeHandle,
                 IntPtr Overlapped);


        [DllImport("vmbuspiper.dll", EntryPoint = "VmbusPipeServerOfferChannel")]
        public static extern SafeFileHandle VmbusPipeServerOfferChannel(
            [In] IntPtr Offer,
            uint OpenMode,
            uint PipeMode);

    }
}