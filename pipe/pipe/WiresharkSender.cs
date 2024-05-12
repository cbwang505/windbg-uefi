/**************************************************************************
*                           MIT License
* 
* Copyright (C) 2015 Frederic Chaxel <fchaxel@free.fr>
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be included
* in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
*********************************************************************/
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using pipe;
using Microsoft.Win32.SafeHandles;
using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;

//
// object creation could be done with 
//      var ws=new Wireshark.WiresharkSender("bacnet",165);  // pipe name is \\.\pipe\bacnet
//
// data to wireshark could be sent with something like that
//      if (ws.isConnected)
//          ws.SendToWireshark(new byte[]{0x55,0xFF,0,5,6,0,0,4}, 0, 8);
//
// Wireshark can be launch with : Wireshark -ni \\.\pipe\bacnet
//
// ... enjoy
//
namespace Wireshark
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    class KD_PACKET
    {
        public UInt32 PacketLeader;
        public UInt16 PacketType;
        public UInt16 ByteCount;
        public UInt32 PacketId;
        public UInt32 Checksum;

        public KD_PACKET(bool newobj)
        {
            PacketLeader = 0;
            PacketType = 0;
            ByteCount = 0;
            PacketId = 0;
            Checksum = 0;
        }

        public byte[] ToByteArray()
        {
            int rawsize = Marshal.SizeOf(this);//Get size of struct data
            byte[] rawdatas = new byte[rawsize];//declare byte array and initialize its size
            IntPtr ptr = Marshal.AllocHGlobal(rawsize);//pointer to byte array
            Marshal.StructureToPtr(this, ptr, true);
            Marshal.Copy(ptr, rawdatas, 0, rawsize);
            Marshal.FreeHGlobal(ptr);
            return rawdatas;
        }

    }

    class KD_PACKET_ALL
    {
        public KD_PACKET packet;
        public byte[] data;

        public KD_PACKET_ALL(KD_PACKET packet, byte[] data)
        {
            this.packet = packet;
            this.data = data;
        }

        public byte[] ToByteArray()
        {
           
            List<byte> rawdatas= packet.ToByteArray().ToList();
            rawdatas.AddRange(data);
            return rawdatas.ToArray();
        }

        public void ValidatePacket()
        {
            if (data.Length > 0)
            {
                if (data.Last() != 0xaa)
                {
                    Console.WriteLine(Utils.HexDump(ToByteArray()));
                    Console.WriteLine("ValidatePacket failed");
                }
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    class VMBUSPIPE_HDR
    {
        public UInt32 magic;
        public UInt32 flag;
        public UInt32 msgsize;
        public UInt32 seqnum;
        public UInt32 checksum;
        public UInt32 magicend;

        public VMBUSPIPE_HDR(bool newobj)
        {
            magic = 0;
            magicend = 0;
            msgsize = 0;
            checksum = 0;
            flag = 0;
            seqnum = 0;
        }
        public VMBUSPIPE_HDR(UInt32 sizemsg, UInt32 seqnumval) : this(sizemsg, seqnumval, 0)
        {

        }
        public VMBUSPIPE_HDR(UInt32 sizemsg, UInt32 seqnumval, UInt32 checksummsg)
        {
            magic = WiresharkSender.magichdr;
            magicend = WiresharkSender.magichdrend;
            msgsize = sizemsg;
            checksum = checksummsg;
            seqnum = seqnumval;
            flag = 1;
        }

        public VMBUSPIPE_HDR(bool reply, UInt32 seqnumreply, UInt32 checksummsg)
        {
            magic = WiresharkSender.magicreplyhdr;
            magicend = WiresharkSender.magicreplyhdrend;
            msgsize = 0;
            checksum = checksummsg;
            seqnum = seqnumreply;
            flag = 2;
        }
        public byte[] ToByteArray()
        {
            int rawsize = Marshal.SizeOf(this);//Get size of struct data
            byte[] rawdatas = new byte[rawsize];//declare byte array and initialize its size
            IntPtr ptr = Marshal.AllocHGlobal(rawsize);//pointer to byte array
            Marshal.StructureToPtr(this, ptr, true);
            Marshal.Copy(ptr, rawdatas, 0, rawsize);
            Marshal.FreeHGlobal(ptr);
            return rawdatas;
        }
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct VMBUS_PIPE_SERVER_OFFER
    {

        public Guid VmGuid;
        public
                UInt32 InterruptLatencyInMilliseconds;
        public Guid InterfaceType;
        public Guid InterfaceInstance;
        public UInt32 InterfaceRevision;
        public UInt16 MmioMegabytes;
        public UInt16 Flags;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 112)] // SizeConst指定了数组的大小，这里假设为256字节
        byte[] UserDefined;


        public byte[] ToByteArray()
        {
            int rawsize = Marshal.SizeOf(this);
            byte[] rawdatas = new byte[rawsize];
            GCHandle handle = GCHandle.Alloc(rawdatas, GCHandleType.Pinned);
            IntPtr buffer = handle.AddrOfPinnedObject();
            Marshal.StructureToPtr(this, buffer, true);
            handle.Free();
            return rawdatas;
        }

        public IntPtr ToPtr()
        {
            IntPtr outPtr = Marshal.AllocHGlobal(Marshal.SizeOf(this));
            Marshal.StructureToPtr(this, outPtr, true);
            return outPtr;
        }


        public VMBUS_PIPE_SERVER_OFFER(Guid vmid)
        {
            VmGuid = vmid;
            Guid if_type = Guid.Parse("{A67DFBAE-7897-42AD-9D10-D96156B36958}");
            Guid if_instance = Guid.Parse("{9C7FE450-67FC-41AA-9732-8D4C3ED93DB4}");
            InterfaceType = if_type;
            InterfaceInstance = if_instance;
            InterfaceRevision = 0;
            MmioMegabytes = 0;
            Flags = 0;
            InterruptLatencyInMilliseconds = 0;
            UserDefined = System.Linq.Enumerable.Repeat((byte)0, 112).ToArray();
        }
        public static IntPtr NewOffer(Guid vmid)
        {

            VMBUS_PIPE_SERVER_OFFER inst = new VMBUS_PIPE_SERVER_OFFER(vmid);
            return inst.ToPtr();

        }
    }


    // Pcap Global Header
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct pcap_hdr_g
    {
        UInt32 magic_number;   /* magic number */
        UInt16 version_major;  /* major version number */
        UInt16 version_minor;  /* minor version number */
        Int32 thiszone;       /* GMT to local correction */
        UInt32 sigfigs;        /* accuracy of timestamps */
        UInt32 snaplen;        /* max length of captured packets, in octets */
        UInt32 network;        /* data link type */

        public pcap_hdr_g(UInt32 snaplen, UInt32 network)
        {
            magic_number = 0xa1b2c3d4;
            version_major = 2;
            version_minor = 4;
            thiszone = 0;
            sigfigs = 0;
            this.snaplen = snaplen;
            this.network = network;
        }

        // struct Marshaling
        // Maybe a 'manual' byte by byte serialization could be required on some systems
        // work well on Win32, Win64 .NET 3.0 to 4.5
        public byte[] ToByteArray()
        {
            int rawsize = Marshal.SizeOf(this);
            byte[] rawdatas = new byte[rawsize];
            GCHandle handle = GCHandle.Alloc(rawdatas, GCHandleType.Pinned);
            IntPtr buffer = handle.AddrOfPinnedObject();
            Marshal.StructureToPtr(this, buffer, false);
            handle.Free();
            return rawdatas;
        }
    }

    // Pcap Packet Header
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct pcap_hdr_p
    {
        UInt32 ts_sec;         /* timestamp seconds */
        UInt32 ts_usec;        /* timestamp microseconds */
        UInt32 incl_len;       /* number of octets of packet saved in file */
        UInt32 orig_len;       /* actual length of packet */

        public pcap_hdr_p(UInt32 lenght, UInt32 datetime, UInt32 microsecond)
        {
            incl_len = orig_len = lenght;
            ts_sec = datetime;
            ts_usec = microsecond;
        }

        // struct Marshaling
        // Maybe a 'manual' byte by byte serialise could be required on some system
        public byte[] ToByteArray()
        {
            int rawsize = Marshal.SizeOf(this);
            byte[] rawdatas = new byte[rawsize];
            GCHandle handle = GCHandle.Alloc(rawdatas, GCHandleType.Pinned);
            IntPtr buffer = handle.AddrOfPinnedObject();
            Marshal.StructureToPtr(this, buffer, false);
            handle.Free();
            return rawdatas;
        }
    }

    public class VmbusWriteInfo
    {
        public IntPtr writePtr;
        public int writelen;

        public VmbusWriteInfo(IntPtr writePtr, int writelen)
        {
            this.writePtr = writePtr;
            this.writelen = writelen;
        }
    }

    public class WiresharkSender
    {

        public static bool SyncFeedBack = false;
        NamedPipeServerStream WiresharkPipe;
        private NamedPipeClientStream pipeClient;
        private NamedPipeServerStream pipeServer;
        private byte[] inbufClient;
        private byte[] outbufClient;
        private byte[] inbufServer;
        private byte[] outbufServer;
        private List<byte> wiresharkbufferClient = new List<byte>();
        private List<byte> wiresharkbufferServer = new List<byte>();
        public static Mutex inbufClientcachelock = new Mutex();
        public static SemaphoreSlim serverreadlock = new SemaphoreSlim(1);
        private ConcurrentQueue<List<byte>> inbufClientcache = new ConcurrentQueue<List<byte>>();
       
        public static WiresharkSender Current;
        /*
        private byte[] magic_bytes =
        {
            0x4d, 0x44, 0x42, 0x47
        };
        */
        public static UInt32 magichdr = 0x56867960;
        public static UInt32 magichdrend = 0x87283679;
        public static UInt32 magicreplyhdr = 0x15957899;
        public static UInt32 magicreplyhdrend = 0x36133574;
        private static byte[] magic_bytes = System.Linq.Enumerable.Repeat((byte)0x30, 4).ToArray();
        private static byte[] magic_bytes_ctrl = System.Linq.Enumerable.Repeat((byte)0x69, 4).ToArray();
        private static byte[] magic_bytes_break = System.Linq.Enumerable.Repeat((byte)0x62, 4).ToArray();
        static private byte[] magic_frame_a = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x08, 0x00
        };
        static private byte[] magic_frame_b = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0x08, 0x00
        };
        private int DefaultBufferLength = 0x2000;
        public static Mutex nodelocksvr = new Mutex();
        //  public staticMutex nodelockclt = new Mutex();
        public static Mutex nodelockclt = nodelocksvr;
        bool IsConnected = false;
        bool VmbusConnected = false;
        public static int windbgfirstresetrevc = 2;
        public static UInt32 gseqnum = 0x5686;
        public static UInt32 gseqnumchk = 0;
        string pipe_name;
        string pipeServer_pipe_name;
        string pipeClient_pipe_name;
        UInt32 pcap_netid;

        object verrou = new object();

        private Guid vmguiid;
        // private static System.Threading.Timer timer = null;

        static byte[] DbgKdContinueApi2Bytes = {
            0x30, 0x30, 0x30, 0x30, 0x02, 0x00, 0x38, 0x00,
            0x01, 0x00, 0x80, 0x80, 0x9d, 0x00, 0x00, 0x00,
            0x3c, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x24, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xaa
        };

        public static volatile ConcurrentDictionary<UInt32,VmbusWriteInfo> FeedbackSListeqList = new ConcurrentDictionary<UInt32, VmbusWriteInfo>();
        private static byte[] readbufasync = System.Linq.Enumerable.Repeat((byte)0, 0x100).ToArray();
        static IntPtr bufferPtrasync;

        public  static bool WindbgPacketHeaderMatch(byte[] cmpbuffrom )
        {
            if (cmpbuffrom.Length < 4)
            {
                return false;

            }

            byte[] cmpbuf = cmpbuffrom.Take(4).ToArray();

            if (cmpbuf.SequenceEqual(magic_bytes) | cmpbuf.SequenceEqual(magic_bytes_ctrl) | cmpbuf.SequenceEqual(magic_bytes_break))
            {
                return true;
            }
            return false;

        }
        private static SafeFileHandle pipinst;

        private static Kernel32.LPOVERLAPPED_COMPLETION_ROUTINE readCompletionRoutine;
        // private static VmbusWindbgProtocol gWindbgProtocol = VmbusWindbgProtocol.VmbusChannelSync;
        private static VmbusWindbgProtocol gWindbgProtocol = VmbusWindbgProtocol.VmbusChannelAsync;
        // private static VmbusWindbgProtocol gWindbgProtocol = VmbusWindbgProtocol.NativeCom;
        private static Kernel32.LPOVERLAPPED_COMPLETION_ROUTINE writeCompletionRoutine;
        //public WiresharkSender(string pipe_name, string pipeServer_pipe, string pipeClient_pipe,UInt32 pcap_netid)
        public WiresharkSender(string pipeServer_pipe, string pipeClient_pipe)
        {
            Current = this;
            pipeServer_pipe_name = pipeServer_pipe;
            pipeClient_pipe_name = pipeClient_pipe;

            Thread th2 = new Thread(PipeCreateWindbg);
            th2.IsBackground = true;
            th2.Start();
        }

        public void WiresharCreate(string pipe_name, UInt32 pcap_netid)
        {
            this.pipe_name = pipe_name;
            this.pcap_netid = pcap_netid;

            // Open the pipe and wait to Wireshark on a background thread
            Thread th = new Thread(PipeCreate);
            th.IsBackground = true;
            th.Start();
        }

        private void PipeCreate()
        {

            try
            {
                WiresharkPipe = new NamedPipeServerStream(pipe_name, PipeDirection.Out, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                // Wait
                WiresharkPipe.WaitForConnection();
                Console.WriteLine("WiresharkPipe IsConnected,,Wireshark session established");
                // Wireshark Global Header
                pcap_hdr_g p = new pcap_hdr_g(65535, pcap_netid);
                byte[] bh = p.ToByteArray();
                WiresharkPipe.Write(bh, 0, bh.Length);
                WiresharkPipe.Flush();
                IsConnected = true;

            }
            catch { }

        }


        private void PipeCreateWindbg()
        {
            try
            {
                pipeServer =
                    new NamedPipeServerStream(pipeServer_pipe_name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);

                pipeServer.WaitForConnection();
                Console.WriteLine("pipeServer:=> " + pipeServer_pipe_name + " Is Connected ,Server session established");
                if (gWindbgProtocol == VmbusWindbgProtocol.NativeCom)
                {
                    pipeClient =
                    new NamedPipeClientStream(".", pipeClient_pipe_name, PipeDirection.InOut, PipeOptions.Asynchronous);

                    pipeClient.Connect();
                    Console.WriteLine("pipeClient:=> " + pipeClient_pipe_name +
                                      " Is Connected ,Client session established");

                }

                inbufClient = new byte[DefaultBufferLength];

                outbufClient = new byte[DefaultBufferLength];

                inbufServer = new byte[DefaultBufferLength];

                outbufServer = new byte[DefaultBufferLength];
                if (gWindbgProtocol == VmbusWindbgProtocol.NativeCom)
                {
                    Console.WriteLine("pipeClient.InBufferSize:=>" + pipeClient.InBufferSize +
                                      " pipeClient.OutBufferSize:=>" + pipeClient.OutBufferSize +
                                      "pipeServer.InBufferSize:=>" + pipeServer.InBufferSize +
                                      "pipeServer.OutBufferSize:=>" + pipeServer.OutBufferSize);


                }
                else
                {

                    Console.WriteLine("pipeServer.InBufferSize:=>" + pipeServer.InBufferSize +
                                      "pipeServer.OutBufferSize:=>" + pipeServer.OutBufferSize);
                }
                //timer =  new System.Threading.Timer(Timer_Elapsed, null, TimeSpan.FromSeconds(160), TimeSpan.FromSeconds(0));


                if (gWindbgProtocol == VmbusWindbgProtocol.NativeCom)
                {
                    Thread th1 = new Thread(PipeRead);
                    th1.IsBackground = true;
                    th1.Start();
                }

                Thread th2 = new Thread(PipeWrite);
                th2.IsBackground = true;
                th2.Start();
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        public void PipeOfferChannel(Guid vmid)
        {
            vmguiid = vmid;
            if (gWindbgProtocol == VmbusWindbgProtocol.VmbusChannelSync)
            {
                Thread th3 = new Thread(PipeOfferChannelWork);
                th3.IsBackground = true;
                th3.Start();
            }
            else
            {
                Thread th3 = new Thread(PipeOfferChannelWorkAsync);
                th3.IsBackground = true;
                th3.Start();
                Thread th4 = new Thread(VmbusWriteQueue);
                th4.IsBackground = true;
                th4.Start();
            }


        }

        private static List<byte> UnpackAfterVmbusRead(List<byte> rawpacket)
        {
           
            int hdrlen = Marshal.SizeOf(typeof(VMBUSPIPE_HDR));
            int alllen = rawpacket.Count;
            int remainlenfoud = 0;
            Dictionary<UInt32, List<byte>> seqdic = new Dictionary<UInt32, List<byte>>();
            List<byte> oueBytes = new List<byte>();
            // List<int> splitls = new List<int>();
            KeyValuePair<UInt32, List<byte>> firstoue = UnpackAfterVmbusReadInternal(rawpacket, true);


            remainlenfoud += firstoue.Value.Count + hdrlen;

            if (firstoue.Key > 0&& firstoue.Value.Count>0)
            {
                seqdic.Add(firstoue.Key, firstoue.Value);
            }

            while (true)
            {
                int remainlen = rawpacket.Count - remainlenfoud;
                if (remainlen >= hdrlen)
                {
                    KeyValuePair<UInt32, List<byte>> afterpue = UnpackAfterVmbusReadInternal(rawpacket.Skip(remainlenfoud).ToList(), true);
                    UInt32 tmpseq = afterpue.Key;
                    if (tmpseq == 0)
                    {
                        remainlenfoud += hdrlen;
                        continue;
                    }
                    //就是发包回包类型
                    if (afterpue.Value.Count == 0)
                    {
                        remainlenfoud += hdrlen;
                        continue;
                    }

                    if (tmpseq == 0 && afterpue.Value.Count == 0)
                    {
                        break;
                    }
                    while (seqdic.ContainsKey(tmpseq))
                    {
                        Console.WriteLine("UnpackAfterVmbusRead seq:=>" + tmpseq);
                        tmpseq += 1;
                    }
                    seqdic.Add(tmpseq, afterpue.Value);

                    remainlenfoud += afterpue.Value.Count + hdrlen;
                    continue;
                }
                else
                {
                    break;
                }
            }

            if (!seqdic.Any())
            {
                return oueBytes;
            }

            if (seqdic.Count > 1)
            {
                Console.WriteLine("UnpackAfterVmbusRead split :=> " + string.Join(",", seqdic.Select(h => h.Value.Count).Select(h => h.ToString("x"))));
            }

            foreach (KeyValuePair<uint, List<byte>> kv in seqdic.OrderBy(h => h.Key))
            {
                oueBytes.AddRange(kv.Value);
            }

            int alllenchk = seqdic.Sum(h => h.Value.Count + hdrlen);

            if (alllen != alllenchk)
            {
                Console.WriteLine("UnpackAfterVmbusRead alllen :=> " + alllen.ToString("x") + " ,alllenchk :=> " +
                                  alllenchk.ToString("x"));
            }
            foreach (KeyValuePair<uint, List<byte>> kv in seqdic)
            {
                if (kv.Key != 0&& SyncFeedBack)
                {
                    uint lpNumberOfBytesWritten = 0;
                    UInt32 tmpseq = kv.Key;

                    VMBUSPIPE_HDR hdr = new VMBUSPIPE_HDR(true, tmpseq, 0);
                    List<byte> hdrbyte = hdr.ToByteArray().ToList();
                    UInt32 Checksum = GenChecksum(hdrbyte);
                    VMBUSPIPE_HDR hdrnew = new VMBUSPIPE_HDR(true, tmpseq, Checksum);
                    List<byte> hdrbytenew = hdrnew.ToByteArray().ToList();
                    byte[] writebufvmbus = hdrbytenew.ToArray();
                    //Console.WriteLine(Utils.HexDump(writebufvmbus, writebufvmbus.Length));
                    IntPtr writebufvmbusptr = Marshal.AllocHGlobal(writebufvmbus.Length); //pointer to byte array
                    Marshal.Copy(writebufvmbus, 0, writebufvmbusptr, writebufvmbus.Length);
                    bool ret = Kernel32.WriteFile(pipinst.DangerousGetHandle(), writebufvmbusptr,
                        (uint)writebufvmbus.Length,
                        ref lpNumberOfBytesWritten,
                        IntPtr.Zero);
                    if (!ret)
                    {
                        Console.WriteLine("WriteFile Vmbus GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
                        Environment.Exit(0);
                    }
                    else
                    {
                        Console.WriteLine("UnpackAfterVmbusRead sync to vm seq:=>" + tmpseq.ToString("x"));
                    }
                }
            }
            return oueBytes;

        }

        private static KD_PACKET UnpackWinbdgPact(List<byte> rawpacket)
        {
            int pcklen = Marshal.SizeOf(typeof(KD_PACKET));
            if (rawpacket.Count < pcklen)
            {
                Console.WriteLine("UnpackWinbdgPact!KD_PACKET failed\r\n");
                Environment.Exit(0);
                return new KD_PACKET(true);
            }

            byte[] rawdatas = rawpacket.Take(pcklen).ToArray();
            IntPtr ptr = Marshal.AllocHGlobal(pcklen);//pointer to byte array
            KD_PACKET pck = new KD_PACKET(true);
            Marshal.Copy(rawdatas, 0, ptr, pcklen);
            Marshal.PtrToStructure(ptr, pck);

            return pck;
        }

        private static KeyValuePair<UInt32, List<byte>> UnpackAfterVmbusReadInternal(List<byte> rawpacket, bool first)
        {
            List<byte> oueBytes = new List<byte>();
            int hdrlen = Marshal.SizeOf(typeof(VMBUSPIPE_HDR));
            if (rawpacket.Count < hdrlen)
            {
                if (first)
                {
                    Console.WriteLine("vmbus_receivepacket_windbg_unpack!hdrlen failed\r\n");
                    Console.WriteLine(Utils.HexDump(rawpacket));

                }
                return new KeyValuePair<uint, List<byte>>(0, oueBytes);
            }

            byte[] rawdatas = rawpacket.Take(hdrlen).ToArray();
            IntPtr ptr = Marshal.AllocHGlobal(hdrlen);//pointer to byte array
            VMBUSPIPE_HDR hdr = new VMBUSPIPE_HDR(true);
            Marshal.Copy(rawdatas, 0, ptr, hdrlen);
            Marshal.PtrToStructure(ptr, hdr);
            UInt32 hdrseq = hdr.seqnum;

            if (hdr.magic == magicreplyhdr && hdr.magicend == magicreplyhdrend)
            {
                if (hdr.flag != 3 && hdr.msgsize != 0)
                {
                    Console.WriteLine(Utils.HexDump(rawpacket));
                    Console.WriteLine("vmbus_receivepacket_windbg_unpack!magic flag failed\r\n");
                }
                UInt32 checksum1 = hdr.checksum;
                hdr.checksum = 0;

                List<byte> hdrbyte1 = hdr.ToByteArray().ToList();

                UInt32 Checksumnew1 = GenChecksum(hdrbyte1);
                if (checksum1 != Checksumnew1)
                {
                    if (first)
                    {
                        Console.WriteLine(Utils.HexDump(rawpacket));
                        Console.WriteLine("vmbus_receivepacket_windbg_unpack!checksum  flag failed :=>" + checksum1.ToString("x") + " ,Checksumnew:=>" + Checksumnew1.ToString("x"));
                    }

                }

                if (SyncFeedBack)
                {

                    VmbusWriteInfo writinf;
                    if (FeedbackSListeqList.TryRemove(hdr.seqnum, out writinf))
                    {
                        Marshal.FreeHGlobal(writinf.writePtr);
                        Console.WriteLine("vmbus_receivepacket_windbg_unpack! feedback from vm :=>" +
                                          hdr.seqnum.ToString("x"));

                        serverreadlock.Release();
                    }
                    else
                    {
                        Console.WriteLine("vmbus_receivepacket_windbg_unpack! feedback TryGetValue failed  vm :=>" +
                                          hdr.seqnum.ToString("x"));
                        Environment.Exit(0);
                    }
                }

                return new KeyValuePair<UInt32, List<byte>>(hdr.seqnum, oueBytes);
            }



            if (hdr.magic != magichdr && hdr.magicend != magichdrend)
            {
                if (first)
                {
                    Console.WriteLine(Utils.HexDump(rawpacket));
                    Console.WriteLine("vmbus_receivepacket_windbg_unpack!magic failed\r\n");
                }

                return new KeyValuePair<uint, List<byte>>(0, oueBytes);
            }

            UInt32 checksum = hdr.checksum;

            int packlen = (int)hdr.msgsize;

            if (packlen == 0 || packlen > rawpacket.Count - hdrlen)
            {
                if (first)
                {
                    Console.WriteLine(Utils.HexDump(rawpacket));
                    Console.WriteLine("vmbus_receivepacket_windbg_unpack!packlen check failed\r\n");
                }

                return new KeyValuePair<uint, List<byte>>(0, oueBytes);
            }

            hdr.checksum = 0;

            List<byte> hdrbyte = hdr.ToByteArray().ToList();
            hdrbyte.AddRange(rawpacket.Skip(hdrlen).Take(packlen));
            UInt32 Checksumnew = GenChecksum(hdrbyte);

            if (gseqnumchk == 0)
            {
                gseqnumchk = hdrseq;
            }
            else
            {
                if (gseqnumchk == hdrseq)
                {
                    Console.WriteLine("vmbus_receivepacket_windbg_unpack!seq check failed seq:=>"+ gseqnumchk.ToString("x"));
                    Environment.Exit(0);
                }
                else
                {
                    gseqnumchk = hdrseq;
                }

            }
            if (checksum != Checksumnew)
            {
                if (first)
                {
                    Console.WriteLine(Utils.HexDump(rawpacket));
                    Console.WriteLine("vmbus_receivepacket_windbg_unpack!checksum failed :=>" + checksum.ToString("x") + " ,Checksumnew:=>" + Checksumnew.ToString("x"));
                }
                if (rawpacket.Skip(hdrlen).Take(packlen).Last() == 0xaa)
                {
                    Console.WriteLine("vmbus_receivepacket_windbg_unpack!checksum failed need fix :=>" + checksum.ToString("x") + " ,Checksumnew:=>" + Checksumnew.ToString("x"));
                   
                    new KeyValuePair<uint, List<byte>>(hdrseq, rawpacket.Skip(hdrlen).Take(packlen).ToList()); ;
                }
                return new KeyValuePair<uint, List<byte>>(0, oueBytes);
            }
           

            return new KeyValuePair<uint, List<byte>>(hdrseq, rawpacket.Skip(hdrlen).Take(packlen).ToList()); ;

        }

        private static volatile bool AfterVmbusReadentered = false;

        private static void AfterVmbusRead(uint dwErrorCode, uint dwNumberOfBytesTransfered, ref OVERLAPPED lpOverlapped)
        {
            AfterVmbusReadentered = true;

            Console.WriteLine("AfterVmbusRead:=> " + dwErrorCode + " lpNumberOfBytesRead:=>" + dwNumberOfBytesTransfered.ToString("x"));

          

            //Console.WriteLine("pipeClient EndRead " + lenread);
            int lenread = (int)dwNumberOfBytesTransfered;
            if (lenread == 0)
            {

                ScheduleNextVmbusReadFile(lenread);
            }
            if (dwNumberOfBytesTransfered > 0xe00)
            {
                // Console.WriteLine(Utils.HexDump(WiresharkSender.Current.outbufClient.Take(lenread).ToList()));
                Console.WriteLine("AfterVmbusRead:=>loog DefaultBufferLength lpNumberOfBytesRead:=>" + dwNumberOfBytesTransfered.ToString("x"));
            }
            byte[] oueBytes = UnpackAfterVmbusRead(WiresharkSender.Current.outbufClient.Take(lenread).ToList()).ToArray();
            // Console.WriteLine(Utils.HexDump(oueBytes.ToArray()));
            lenread = oueBytes.Length;
            if (lenread > 0)
            {
                WiresharkSender.Current.SendToWireshark(oueBytes, false);


                byte[] tmpwrite = new byte[lenread];


                Array.Copy(oueBytes, 0, tmpwrite, 0, lenread);
                /*WiresharkSender.Current.pipeServer.BeginWrite(WiresharkSender.Current.inbufServer, 0, lenread,
                    pipeClientBeginWriteAsyncCallback, lenread);*/

              //  Console.WriteLine("Schedule WiresharkSender.Current.pipeServer.BeginWrite:=> " + lenread + " lpNumberOfBytesRead:=>" + lenread);
                WiresharkSender.Current.pipeServer.BeginWrite(tmpwrite, 0, lenread,
                   pipeClientBeginWriteAsyncCallback, lenread);

                // WiresharkSender.Current.pipeServer.Write(WiresharkSender.Current.inbufServer, 0, lenread);
            }
            else
            {
                if (gWindbgProtocol == VmbusWindbgProtocol.VmbusChannelAsync)
                {

                    ScheduleNextVmbusReadFile(lenread);

                }

                //   Console.WriteLine("p
            }

        }

        private static void AfterVmbusWrite(uint dwErrorCode, uint dwNumberOfBytesTransfered, ref OVERLAPPED lpOverlapped)
        {
            Console.WriteLine("AfterVmbusWrite:=> " + dwErrorCode + " lpNumberOfBytesWritten:=>" + dwNumberOfBytesTransfered);

            /*byte[] writebuf = System.Linq.Enumerable.Range(0, 0x100).Select(h => Convert.ToByte((h+ dwNumberOfBytesTransfered) & 0xff)).ToArray();

            GCHandle writebufhandle = GCHandle.Alloc(writebuf, GCHandleType.Pinned);
            IntPtr writebufPtr = writebufhandle.AddrOfPinnedObject();
            bool ret = Kernel32.WriteFileEx(pipinst.DangerousGetHandle(), writebufPtr, (uint)writebuf.Length, ref lpOverlapped,
                writeCompletionRoutine);
            if (!ret)
            {
                Console.WriteLine("GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
            }
            Console.WriteLine("Schedule WriteFile:=> " + ret + " lpNumberOfBytesWritten:=>" + writebuf.Length);
            Console.WriteLine(Utils.HexDump(writebuf));*/
        }

        private void PipeOfferChannelWorkAsync()
        {
            OVERLAPPED lpOverlappedRead = new OVERLAPPED();
            OVERLAPPED lpOverlappedWrite = new OVERLAPPED();
            readCompletionRoutine =
                (Kernel32.LPOVERLAPPED_COMPLETION_ROUTINE)Delegate.CreateDelegate(
                    typeof(Kernel32.LPOVERLAPPED_COMPLETION_ROUTINE), typeof(WiresharkSender).GetMethod("AfterVmbusRead", BindingFlags.Static | BindingFlags.NonPublic));

            writeCompletionRoutine =
           (Kernel32.LPOVERLAPPED_COMPLETION_ROUTINE)Delegate.CreateDelegate(
               typeof(Kernel32.LPOVERLAPPED_COMPLETION_ROUTINE), typeof(WiresharkSender).GetMethod("AfterVmbusWrite", BindingFlags.Static | BindingFlags.NonPublic));

            IntPtr offerinf = VMBUS_PIPE_SERVER_OFFER.NewOffer(vmguiid);
            pipinst = Vmbuspiper.VmbusPipeServerOfferChannel(offerinf, 0x40000000, 0);
            if (!pipinst.IsInvalid)
            {
                Console.WriteLine("VmbusPipe:=> " + vmguiid + " Is Connected ,Vmbus session established");
                bool ret = Vmbuspiper.VmbusPipeServerConnectPipe(pipinst.DangerousGetHandle(), IntPtr.Zero);

                if (ret)
                {
                    Console.WriteLine("VmbusPipe:=> " + vmguiid + " Open ok");
                    VmbusConnected = true;
                    if (gWindbgProtocol == VmbusWindbgProtocol.NativeCom)
                    {
                        byte[] writebuf = System.Linq.Enumerable.Range(0, 0x100).Select(h => Convert.ToByte(h & 0xff))
                            .ToArray();
                        GCHandle readbufhandle = GCHandle.Alloc(readbufasync, GCHandleType.Pinned);
                        bufferPtrasync = readbufhandle.AddrOfPinnedObject();

                        ret = Kernel32.ReadFileEx(pipinst.DangerousGetHandle(), bufferPtrasync,
                            (uint)readbufasync.Length, ref lpOverlappedRead,
                            readCompletionRoutine);
                        if (!ret)
                        {
                            Console.WriteLine("GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
                        }

                        Console.WriteLine("ReadFile:=> " + ret + " lpNumberOfBytesRead:=>" + readbufasync.Length);

                        GCHandle writebufhandle = GCHandle.Alloc(writebuf, GCHandleType.Pinned);
                        IntPtr writebufPtr = writebufhandle.AddrOfPinnedObject();
                        ret = Kernel32.WriteFileEx(pipinst.DangerousGetHandle(), writebufPtr, (uint)writebuf.Length,
                            ref lpOverlappedWrite,
                            writeCompletionRoutine);
                        if (!ret)
                        {
                            Console.WriteLine("GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
                        }

                        Console.WriteLine("WriteFile:=> " + ret + " lpNumberOfBytesWritten:=>" + writebuf.Length);
                        Console.WriteLine(Utils.HexDump(writebuf));
                        ;
                    }
                    else
                    {
                        GCHandle readbufhandle = GCHandle.Alloc(outbufClient, GCHandleType.Pinned);
                        bufferPtrasync = readbufhandle.AddrOfPinnedObject();

                        ret = Kernel32.ReadFileEx(pipinst.DangerousGetHandle(), bufferPtrasync,
                            (uint)outbufClient.Length, ref lpOverlappedRead,
                            readCompletionRoutine);
                        if (!ret)
                        {
                            Console.WriteLine("ReadFileEx GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
                        }

                        Console.WriteLine("ReadFile:=> " + ret + " lpNumberOfBytesRead:=>" + outbufClient.Length);

                    }




                    while (true)
                    {
                        Kernel32.SleepEx(10, true);
                    }
                }
            }
            else
            {

                Console.WriteLine("VmbusPipe:=> " + vmguiid + " Is Connected ,VmbusP session Is Invalid");
            }

        }

        private void PipeOfferChannelWork()
        {
            IntPtr offerinf = VMBUS_PIPE_SERVER_OFFER.NewOffer(vmguiid);
            pipinst = Vmbuspiper.VmbusPipeServerOfferChannel(offerinf, 0x40000000, 0);
            if (!pipinst.IsInvalid)
            {
                Console.WriteLine("VmbusPipe:=> " + vmguiid + " Is Connected ,Vmbus session established");
                bool ret = Vmbuspiper.VmbusPipeServerConnectPipe(pipinst.DangerousGetHandle(), IntPtr.Zero);
                if (ret)
                {
                    Console.WriteLine("VmbusPipe:=> " + vmguiid + " Open ok");

                }

                if (gWindbgProtocol == VmbusWindbgProtocol.NativeCom)
                {
                    VmbusConnected = true;
                    if (false)
                    {
                        byte[] readbuf = new byte[0x100];
                        byte[] readbuf2 = new byte[0x100];
                        byte[] writebuf = System.Linq.Enumerable.Range(0, 0x100).Select(h => Convert.ToByte(h & 0xff))
                            .ToArray();
                        GCHandle readbufhandle = GCHandle.Alloc(readbuf, GCHandleType.Pinned);
                        IntPtr bufferPtr = readbufhandle.AddrOfPinnedObject();
                        uint lpNumberOfBytesRead = 0;
                        uint lpNumberOfBytesWritten = 0;
                        ret = Kernel32.ReadFile(pipinst.DangerousGetHandle(), bufferPtr, (uint)readbuf.Length,
                            ref lpNumberOfBytesRead,
                            IntPtr.Zero);
                        if (!ret)
                        {
                            Console.WriteLine("GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
                        }

                        Console.WriteLine("ReadFile:=> " + ret + " lpNumberOfBytesRead:=>" + lpNumberOfBytesRead);
                        Console.WriteLine(Utils.HexDump(readbuf));
                        GCHandle writebufhandle = GCHandle.Alloc(writebuf, GCHandleType.Pinned);
                        IntPtr writebufPtr = writebufhandle.AddrOfPinnedObject();
                        ret = Kernel32.WriteFile(pipinst.DangerousGetHandle(), writebufPtr, (uint)writebuf.Length,
                            ref lpNumberOfBytesWritten,
                            IntPtr.Zero);
                        if (!ret)
                        {
                            Console.WriteLine("GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
                        }

                        Console.WriteLine("WriteFile:=> " + ret + " lpNumberOfBytesWritten:=>" +
                                          lpNumberOfBytesWritten);
                        Console.WriteLine(Utils.HexDump(writebuf));
                        lpNumberOfBytesRead = 0;
                        lpNumberOfBytesWritten = 0;
                        GCHandle readbufhandle2 = GCHandle.Alloc(readbuf2, GCHandleType.Pinned);
                        IntPtr bufferPtr2 = readbufhandle2.AddrOfPinnedObject();
                        ret = Kernel32.ReadFile(pipinst.DangerousGetHandle(), bufferPtr2, (uint)readbuf2.Length,
                            ref lpNumberOfBytesRead,
                            IntPtr.Zero);
                        if (!ret)
                        {
                            Console.WriteLine("GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
                        }

                        Console.WriteLine("ReadFile:=> " + ret + " lpNumberOfBytesRead:=>" + lpNumberOfBytesRead);
                        Console.WriteLine(Utils.HexDump(readbuf2));
                        byte[] writebuf2 = System.Linq.Enumerable.Range(0, 0x100)
                            .Select(h => Convert.ToByte((h + 0x100) & 0xff)).ToArray();
                        GCHandle writebufhandle2 = GCHandle.Alloc(writebuf2, GCHandleType.Pinned);
                        IntPtr writebufPtr2 = writebufhandle2.AddrOfPinnedObject();
                        ret = Kernel32.WriteFile(pipinst.DangerousGetHandle(), writebufPtr2, (uint)writebuf.Length,
                            ref lpNumberOfBytesWritten,
                            IntPtr.Zero);
                        if (!ret)
                        {
                            Console.WriteLine("GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
                        }

                        Console.WriteLine("WriteFile:=> " + ret + " lpNumberOfBytesWritten:=>" +
                                          lpNumberOfBytesWritten);
                        Console.WriteLine(Utils.HexDump(writebuf2));
                    }
                }
                else
                {
                    while (true)
                    {
                        uint lpNumberOfBytesRead = 0;


                        byte[] outbufClientstack = System.Linq.Enumerable.Repeat((byte)0, DefaultBufferLength).ToArray();

                        IntPtr bufferPtrasyncptr = Marshal.AllocHGlobal(DefaultBufferLength);//pointer to byte array

                        ret = Kernel32.ReadFile(pipinst.DangerousGetHandle(), bufferPtrasyncptr, (uint)DefaultBufferLength,
                            ref lpNumberOfBytesRead,
                            IntPtr.Zero);
                        if (!ret)
                        {
                            Console.WriteLine("ReadFileVmbus GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
                            Environment.Exit(0);
                        }
                        if (lpNumberOfBytesRead > 0)
                        {

                            //Console.WriteLine("pipeClient EndRead " + lenread);
                            int lenread = (int)lpNumberOfBytesRead;
                            Marshal.Copy(bufferPtrasyncptr, outbufClientstack, 0, lenread);
                            byte[] oueBytes =
                                UnpackAfterVmbusRead(outbufClientstack.Take(lenread).ToList())
                                    .ToArray();
                            // Console.WriteLine(Utils.HexDump(oueBytes.ToArray()));
                            lenread = oueBytes.Length;
                            if (lenread > 0)
                            {
                                WiresharkSender.Current.SendToWireshark(oueBytes, false);
                                Array.Copy(oueBytes, 0, WiresharkSender.Current.inbufServer, 0, lenread);
                                WiresharkSender.Current.pipeServer.BeginWrite(WiresharkSender.Current.inbufServer, 0,
                                    lenread, pipeClientBeginWriteAsyncCallback, lenread);
                                if (!VmbusConnected)
                                {
                                    VmbusConnected = true;
                                }
                                Console.WriteLine("ReadFileVmbus:=> " + ret + " lpNumberOfBytesRead:=>" + lpNumberOfBytesRead);
                            }
                            else
                            {
                                Console.WriteLine("ReadFileVmbus UnpackAfterVmbusRead failed lpNumberOfBytesRead:=>" + lpNumberOfBytesRead);
                            }
                        }
                        Marshal.FreeHGlobal(bufferPtrasyncptr);
                        continue;

                    }
                }
            }
            else
            {

                Console.WriteLine("VmbusPipe:=> " + vmguiid + " Is Connected ,VmbusP session Is Invalid");
            }
        }

        private void Timer_Elapsed(object sender)
        {
            Console.WriteLine("Inject DbgKdContinueApi2Bytes");
            //timer.Enabled = false;
            int lenread = DbgKdContinueApi2Bytes.Length;
            SendToWireshark(DbgKdContinueApi2Bytes.ToArray(), true);
            Array.Copy(DbgKdContinueApi2Bytes, 0, inbufClient, 0, lenread);
            pipeClient.BeginWrite(inbufClient, 0, lenread, pipeServerBeginWriteAsyncCallback, lenread);
        }

        private void pipeClientBeginReadAsyncCallback(IAsyncResult ar)
        {
            try
            {


                int lenread = pipeClient.EndRead(ar);
                List<byte> oueBytes = new List<byte>();
                //Console.WriteLine("pipeClient EndRead " + lenread);

                foreach (byte b in outbufClient.Take(lenread))
                {
                    oueBytes.Add(b);
                }
                SendToWireshark(oueBytes.ToArray(), false);
                Array.Copy(outbufClient, 0, inbufServer, 0, lenread);
                pipeServer.BeginWrite(inbufServer, 0, lenread, pipeClientBeginWriteAsyncCallback, lenread);
                pipeClient.BeginRead(outbufClient, 0, DefaultBufferLength, pipeClientBeginReadAsyncCallback, null);

            }
            catch (Exception e)
            {
                Console.WriteLine(e);

                Console.WriteLine("pipeClientBeginReadAsyncCallback  teardown");
                Environment.Exit(0);
                throw;


            }
        }

        private static void ScheduleNextVmbusReadFile(int lenwrite)
        {
            OVERLAPPED lpOverlapped = new OVERLAPPED();
            // WiresharkSender.Current.outbufClient = new byte[WiresharkSender.Current.DefaultBufferLength];
            for (var i = 0; i < WiresharkSender.Current.DefaultBufferLength; i++)
            {
                WiresharkSender.Current.outbufClient[i] = 0;
            }
            GCHandle readbufhandle = GCHandle.Alloc(WiresharkSender.Current.outbufClient, GCHandleType.Pinned);
            bufferPtrasync = readbufhandle.AddrOfPinnedObject();
            bool ret = Kernel32.ReadFileEx(pipinst.DangerousGetHandle(), bufferPtrasync, (uint)WiresharkSender.Current.DefaultBufferLength, ref lpOverlapped,
                readCompletionRoutine);

            while (!ret)
            {
                Console.WriteLine("ReadFileEx GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
                Environment.Exit(0);
                for (var i = 0; i < WiresharkSender.Current.DefaultBufferLength; i++)
                {
                    WiresharkSender.Current.outbufClient[i] = 0;
                }
                GCHandle readbufhandle2 = GCHandle.Alloc(WiresharkSender.Current.outbufClient, GCHandleType.Pinned);
                bufferPtrasync = readbufhandle2.AddrOfPinnedObject();
                ret = Kernel32.ReadFileEx(pipinst.DangerousGetHandle(), bufferPtrasync, (uint)WiresharkSender.Current.DefaultBufferLength, ref lpOverlapped,
                    readCompletionRoutine);
            }
            Console.WriteLine("Schedule ReadFile:=> " + ret + " lpNumberOfBytesRead:=>" + lenwrite.ToString("x"));
            //Console.WriteLine("Schedule ReadFile:=> " + ret + " lpNumberOfBytesRead:=>" + WiresharkSender.Current.outbufClient.Length);
            //
            AfterVmbusReadentered = false;
            while (!AfterVmbusReadentered)
            {
                Kernel32.SleepEx(10, true);
            }
        }
        private static void pipeClientBeginWriteAsyncCallback(IAsyncResult ar)
        {
            int lenwrite = (int)ar.AsyncState;
            Console.WriteLine("Schedule pipeClientBeginWriteAsyncCallback:=> " +  ar.IsCompleted + " lpNumberOfBytesRead:=>" + lenwrite.ToString("x"));
            // timer.Enabled = false;

            WiresharkSender.Current.pipeServer.EndWrite(ar);
            if (gWindbgProtocol == VmbusWindbgProtocol.VmbusChannelAsync)
            {

                ScheduleNextVmbusReadFile(lenwrite);

            }

            //   Console.WriteLine("pipeServer EndWrite " + lenwrite);

        }

        private void PipeRead()
        {
            pipeClient.BeginRead(outbufClient, 0, DefaultBufferLength, pipeClientBeginReadAsyncCallback, null);

        }

        private static UInt32 GenChecksumVal(List<byte> databytes)
        {
            UInt32 Checksum = 0;

            if (databytes.Count != 4)
            {
                Console.WriteLine("GenChecksumVal failed");

                Environment.Exit(0);
            }

            for (int i = 0; i < databytes.Count; i++)
            {
                Checksum |= (UInt32)(((UInt32)databytes[i]) << (i * 8));
            }

            return Checksum;
        }

        private static UInt32 GenChecksum(List<byte> databytes)
        {
            UInt32 Checksum = 0;
            List<byte> databyteschk = new List<byte>();
            databyteschk.AddRange(databytes);
            int padlen = databytes.Count % 4;
            if (padlen > 0)
            {
                for (int i = 0; i < 4 - padlen; i++)
                {
                    databyteschk.Add(0);
                }
            }

            for (int i = 0; i < databyteschk.Count; i += 4)
            {
                List<byte> calcbytes = databyteschk.Skip(i).Take(4).ToList();
                UInt32 Checksumtmp = GenChecksumVal(calcbytes);

                Checksum = Checksum ^ Checksumtmp;

            }

            return Checksum;
        }

        private bool VmbusWriteFulsh(VmbusWriteInfo tp)
        {
            
            /*int idx = 0;
            while (!FeedbackSListeqList.Contains(gseqnumnow))
            {
                idx++;
                /*if (idx > 10)
                {
                    return VmbusWriteFulsh(tp);
                }#1#
                Kernel32.SleepEx(100, true);
            }

            FeedbackSListeqList.Remove(gseqnumnow);
            Console.WriteLine("WriteFile Vmbus feedback recieved :=>"+ gseqnumnow.ToString("x"));
            Marshal.FreeHGlobal(ptr);*/
            
            return true;
        }


        private void VmbusWriteFromRawpart(byte[] tmpwrite)
        {
            gseqnum++;
            int lenread = tmpwrite.Length;

            UInt32 gseqnumnow = gseqnum;


            // Console.WriteLine(Utils.HexDump(tmpwrite, tmpwrite.Length));
            uint lpNumberOfBytesWritten = 0;

            // OVERLAPPED lpOverlappedWrite = new OVERLAPPED();
            VMBUSPIPE_HDR hdr = new VMBUSPIPE_HDR((UInt32)lenread, gseqnumnow);
            List<byte> hdrbyte = hdr.ToByteArray().ToList();
            hdrbyte.AddRange(tmpwrite);
            UInt32 Checksum = GenChecksum(hdrbyte);
            VMBUSPIPE_HDR hdrnew = new VMBUSPIPE_HDR((UInt32)lenread, gseqnumnow, Checksum);
            List<byte> hdrbytenew = hdrnew.ToByteArray().ToList();
            hdrbytenew.AddRange(tmpwrite);
            byte[] writebufvmbus = hdrbytenew.ToArray();

            IntPtr writebufvmbusptr = Marshal.AllocHGlobal(writebufvmbus.Length); //pointer to byte array
            Marshal.Copy(writebufvmbus, 0, writebufvmbusptr, writebufvmbus.Length);
            bool ret = Kernel32.WriteFile(pipinst.DangerousGetHandle(), writebufvmbusptr,
                (uint)writebufvmbus.Length,
                ref lpNumberOfBytesWritten,
                IntPtr.Zero);
            if (!ret)
            {
                Console.WriteLine("WriteFile Vmbus GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
                Environment.Exit(0);
            }

            if (SyncFeedBack)
            {
                VmbusWriteInfo writeinf = new VmbusWriteInfo(writebufvmbusptr, writebufvmbus.Length);
                FeedbackSListeqList.TryAdd(gseqnumnow, writeinf);
            }



            SendToWireshark(tmpwrite.ToArray(), true);

            //Marshal.FreeHGlobal(writebufvmbusptr);



            Console.WriteLine("WriteFile Vmbus:=> " + ret+ " lpNumberOfBytesWritten:=>" +
                              lpNumberOfBytesWritten.ToString("x") + ",seq :=>" + gseqnumnow.ToString("x"));

        }

        private void VmbusWriteQueue()
        {
            int pcklen = Marshal.SizeOf(typeof(KD_PACKET));
            List<byte> stackbuf = new List<byte>();
            while (true)
            {
                List<byte> stackbuftmp = new List<byte>();
                if (inbufClientcache.TryDequeue(out stackbuftmp))
                {
                    stackbuf.AddRange(stackbuftmp);

                }
                else
                {
                    Kernel32.SleepEx(10, true);
                    continue;
                }
                bool haspck = false;
                int stacklen = stackbuf.Count;
                List<KD_PACKET_ALL> stackpacket = new List<KD_PACKET_ALL>();
                int startindx = 0;
                for (int i = 0; i < stacklen; i++)
                {
                    if (WindbgPacketHeaderMatch(stackbuf.Skip(i).ToArray()))
                    {
                        if (stacklen - i >= pcklen)
                        {
                            KD_PACKET pck = UnpackWinbdgPact(stackbuf.Skip(i).Take(pcklen).ToList());
                            if (pck.ByteCount == 0)
                            {
                               
                                if (windbgfirstresetrevc>0)
                                {
                                    if (pck.PacketType == 6)
                                    {
                                        windbgfirstresetrevc--;
                                        stackbuf.Clear();
                                        break;
                                    }
                                }
                                else
                                {
                                    stackpacket.Add(new KD_PACKET_ALL(pck, new byte[] { }));
                                }

                            }
                            else
                            {
                                int remainlen = pck.ByteCount + 1;
                                if (stacklen - i- pcklen >= remainlen)
                                {
                                    KD_PACKET_ALL pckok = new KD_PACKET_ALL(pck,
                                        stackbuf.Skip(i + pcklen).Take(remainlen).ToArray());
                                    pckok.ValidatePacket();
                                    stackpacket.Add(pckok);
                                    if (startindx == 0)
                                    {
                                        startindx = i;
                                    }
                                }
                            }
                        }
                    }
                }

                if (stackpacket.Count > 0)
                {
                    List<byte> stackbufslice = stackbuf.Take(startindx).ToList();

                    stackpacket.ForEach(h => stackbufslice.AddRange(h.ToByteArray()));
                    int slicelen = stackbufslice.Count;
                    VmbusWriteFromRawpart(stackbufslice.ToArray());
                    stackbuf.RemoveRange(0, slicelen);
                }
                else if(SyncFeedBack)
                {
                    serverreadlock.Release();
                }


            }
        }

        private void pipeServerBeginReadAsyncCallback(IAsyncResult ar)
        {
            try
            {
                while (!VmbusConnected)
                {
                    Kernel32.SleepEx(10, true);
                }
                //timer.Change(-1, -1);
                //timer.Enabled = false;
                int lenread = pipeServer.EndRead(ar);
                int rawlen = lenread;
                if (lenread > 0)
                {
                    inbufClientcachelock.WaitOne();
                    inbufClientcache.Enqueue(outbufServer.Take(lenread).ToList());

                    inbufClientcachelock.ReleaseMutex();
                    if (SyncFeedBack)
                    {
                        while (!serverreadlock.Wait(30000))
                        {
                            Console.WriteLine("fix WriteFile timeout");
                            foreach (VmbusWriteInfo vmbusWriteInfo in FeedbackSListeqList.Values)
                            {
                                uint lpNumberOfBytesWritten = 0;
                                bool ret = Kernel32.WriteFile(pipinst.DangerousGetHandle(), vmbusWriteInfo.writePtr,
                                    (uint) vmbusWriteInfo.writelen,
                                    ref lpNumberOfBytesWritten,
                                    IntPtr.Zero);
                                if (!ret)
                                {
                                    Console.WriteLine("WriteFile Vmbus GetLastWin32Error:=>" +
                                                      Marshal.GetLastWin32Error());
                                    Environment.Exit(0);
                                }
                                else
                                {
                                    Console.WriteLine("fix WriteFile Vmbus:=> " + ret + " lpNumberOfBytesWritten:=>" +
                                                      lpNumberOfBytesWritten.ToString("x") + ",seq :=>" +
                                                      gseqnum.ToString("x"));
                                }
                            }
                        }



                    }

                    Console.WriteLine("pipeServer EndRead " + rawlen);

                    if (gWindbgProtocol == VmbusWindbgProtocol.NativeCom)
                    {
                        List<byte> oueBytes = new List<byte>();
                        foreach (byte b in outbufServer.Take(lenread))
                        {
                            oueBytes.Add(b);
                        }

                        SendToWireshark(oueBytes.ToArray(), true);
                        Array.Copy(outbufServer, 0, inbufClient, 0, lenread);
                        pipeClient.BeginWrite(inbufClient, 0, lenread, pipeServerBeginWriteAsyncCallback, lenread);

                    }
                    else if (gWindbgProtocol == VmbusWindbgProtocol.VmbusChannelAsync)
                    {


                        /*while (!VmbusConnected)
                        {
                            Kernel32.SleepEx(10, true);
                        }
                        SendToWireshark(oueBytes.ToArray(), true);
                        OVERLAPPED lpOverlappedWrite = new OVERLAPPED();
    
                        VMBUSPIPE_HDR hdr = new VMBUSPIPE_HDR((UInt32)lenread);
                        List<byte> hdrbyte = hdr.ToByteArray().ToList();
                        hdrbyte.AddRange(oueBytes);
                        UInt32 Checksum = GenChecksum(hdrbyte);
                        VMBUSPIPE_HDR hdrnew = new VMBUSPIPE_HDR((UInt32)lenread, Checksum);
                        List<byte> hdrbytenew = hdrnew.ToByteArray().ToList();
                        hdrbytenew.AddRange(oueBytes);
                        byte[] writebufvmbus = hdrbytenew.ToArray();
                        //Console.WriteLine(Utils.HexDump(writebufvmbus, writebufvmbus.Length));
                        IntPtr writebufvmbusptr = Marshal.AllocHGlobal(writebufvmbus.Length);//pointer to byte array
                        Marshal.Copy( writebufvmbus, 0, writebufvmbusptr, writebufvmbus.Length);
                        bool ret = Kernel32.WriteFileEx(pipinst.DangerousGetHandle(), writebufvmbusptr, (uint)writebufvmbus.Length, ref lpOverlappedWrite,
                              writeCompletionRoutine);
                        if (!ret)
                        {
                            Console.WriteLine("WriteFileEx GetLastWin32Error:=>" + Marshal.GetLastWin32Error());
                        }
                        Console.WriteLine("WriteFile Vmbus:=> " + ret + " lpNumberOfBytesWritten:=>" + writebufvmbus.Length);*/




                        if (lenread >= 0x10)
                        {
                            /*Task.Factory.StartNew((objstack) =>
                            {
    
                                VmbusWriteFulsh(objstack as VmbusWriteInfo);
                            }, writeinf);*/

                        }


                    }
                    else if (gWindbgProtocol == VmbusWindbgProtocol.VmbusChannelSync)
                    {
                        lenread = inbufClientcache.Count;
                        if (lenread >= 0x10)
                        {
                            //  VmbusWriteFulsh();
                        }
                    }
                }

                for (var i = 0; i < WiresharkSender.Current.DefaultBufferLength; i++)
                {
                    WiresharkSender.Current.outbufServer[i] = 0;
                }
                pipeServer.BeginRead(outbufServer, 0, DefaultBufferLength, pipeServerBeginReadAsyncCallback, null);

                /*while (true)
                {
                    Kernel32.SleepEx(10, true);
                }*/
            }
            catch (Exception e)
            {
                Console.WriteLine(e);

                Console.WriteLine("pipeServerBeginReadAsyncCallback  teardown");
                Environment.Exit(0);
                throw;


            }

        }

        private void pipeServerBeginWriteAsyncCallback(IAsyncResult ar)
        {
            // timer.Enabled = true;
            //timer.Change(TimeSpan.FromSeconds(160), TimeSpan.FromSeconds(0));
            int lenwrite = (int)ar.AsyncState;
            pipeClient.EndWrite(ar);
            // Console.WriteLine("pipeClient EndWrite " + lenwrite);

        }

        private void PipeWrite()
        {
            pipeServer.BeginRead(outbufServer, 0, DefaultBufferLength, pipeServerBeginReadAsyncCallback, null);

        }



        public bool isConnected
        {
            get { return IsConnected; }
        }

        private UInt32 DateTimeToUnixTimestamp(DateTime dateTime)
        {
            return (UInt32)(dateTime - new DateTime(1970, 1, 1).ToLocalTime()).TotalSeconds;
        }

        public bool SendToWireshark(byte[] oueBytes, bool fromhost)
        {
            if (fromhost)
            {
                return SendToWiresharkReal(wiresharkbufferServer, oueBytes.ToArray(), 0, oueBytes.Length, fromhost);
            }
            else
            {
                return SendToWiresharkReal(wiresharkbufferClient, oueBytes.ToArray(), 0, oueBytes.Length, fromhost);
            }

        }

        public bool SendToWiresharkReal(List<byte> wiresharkbuffer, byte[] buffer, int offsetorg, int lenght, bool fromhost)
        {
            if (lenght == 0)
            {
                return true;
            }

            if (fromhost)
            {
                nodelocksvr.WaitOne();
            }
            else
            {
                nodelockclt.WaitOne();
            }

            wiresharkbuffer.AddRange(buffer.Take(lenght));
            int oldwiresharkbufferlen = wiresharkbuffer.Count;
            List<int> magicoffsets = new List<int>();
            List<byte[]> splitbuf = new List<byte[]>();
            for (int i = 0; i < wiresharkbuffer.Count; i++)
            {
                if (wiresharkbuffer.Count - i >= magic_bytes.Length)
                {
                    byte[] cmpbuf = wiresharkbuffer.Skip(i).Take(4).ToArray();
                    if (cmpbuf.SequenceEqual(magic_bytes) | cmpbuf.SequenceEqual(magic_bytes_ctrl) | cmpbuf.SequenceEqual(magic_bytes_break))
                    {
                        magicoffsets.Add(i);
                    }
                }
            }

            int startoffset = 0;
            int nextoffset = 0;
            bool startskip = false;
            if (magicoffsets.Count == 1)
            {
                nextoffset = magicoffsets.FirstOrDefault();
                if (nextoffset != 0)
                {
                    splitbuf.Add(wiresharkbuffer.Take(nextoffset).ToArray());
                }
            }
            else
            {
                foreach (int offset in magicoffsets.OrderBy(h => h))
                {
                    if (startoffset == 0 && !startskip)
                    {
                        startskip = true;
                        startoffset = offset;
                        if (startoffset != 0)
                        {
                            splitbuf.Add(wiresharkbuffer.Take(startoffset).ToArray());
                        }
                    }
                    else
                    {
                        if (nextoffset != 0)
                        {
                            startoffset = nextoffset;
                        }

                        nextoffset = offset;
                        int nowlen = nextoffset - startoffset;
                        if (nowlen > 0)
                        {
                            splitbuf.Add(wiresharkbuffer.Skip(startoffset).Take(nowlen).ToArray());
                        }

                    }
                }
            }

            if (nextoffset != 0)
            {
                List<byte> remainbuf = wiresharkbuffer.Skip(nextoffset).ToList();
                wiresharkbuffer.Clear();
                if (remainbuf.Count > 0)
                {
                    wiresharkbuffer.AddRange(remainbuf);
                }
            }
            else if (magicoffsets.Count == 1)
            {
                if (wiresharkbuffer.Count == 1)
                {
                    //wiresharkbuffer.Clear();
                }
            }

            int newwiresharkbufferlen = wiresharkbuffer.Count;
            int writelen = oldwiresharkbufferlen - newwiresharkbufferlen;



            int writecount = 0;
            int magicoffsetscount = magicoffsets.Count;
            int splitbufscount = splitbuf.Count;
            foreach (byte[] tmpbuf in splitbuf.Where(h => h.Length >= 1))
            { //
                byte[] bts = PacketWriter.Current.WritePactet(tmpbuf, fromhost);
                if (IsConnected && bts.Length > 0xe)
                {
                    /*byte[] cmpframe = bts.Take(0xe).ToArray();
                    byte[] cmpbuf = tmpbuf.Take(4).ToArray();
                    if ((cmpframe.SequenceEqual(magic_frame_a)|| cmpframe.SequenceEqual(magic_frame_b))&&(tmpbuf.Length == 0x10 || tmpbuf.Last() == 0xaa) && (cmpbuf.SequenceEqual(magic_bytes) |
                                cmpbuf.SequenceEqual(magic_bytes_ctrl) | cmpbuf.SequenceEqual(magic_bytes_break)))
                    {
                        SendToWireshark(bts, 0, bts.Length, DateTime.Now);
                    }*/

                    SendToWireshark(bts, 0, bts.Length, DateTime.Now);
                }

                writecount++;
            }

            if (fromhost)
            {
                nodelocksvr.ReleaseMutex();
            }
            else
            {
                nodelockclt.ReleaseMutex();
            }


            if (writecount > 0)
            {
                string prefixstr = fromhost ? "windbg to vm" : "vm to windbg";
                Console.WriteLine(prefixstr + " len " + writecount.ToString("x") + " magicoffsets " + magicoffsetscount.ToString("x") + " splitbuf " + splitbufscount.ToString("x") + " oldlen " + oldwiresharkbufferlen.ToString("x") + " newlen " + newwiresharkbufferlen.ToString("x") + " rawlen " + writelen.ToString("x"));
            }

            if (oldwiresharkbufferlen == newwiresharkbufferlen && splitbufscount > 0)
            {
                Console.WriteLine("malformed packet warning");
            }
            return true;
            //  
        }

        public bool SendToWireshark(byte[] buffer, int offset, int lenght, DateTime date)
        {
            UInt32 date_sec, date_usec;

            // Suppress all values for ms, us and ns
            DateTime d2 = new DateTime((date.Ticks / (long)10000000) * (long)10000000);

            date_sec = DateTimeToUnixTimestamp(date);
            date_usec = (UInt32)((date.Ticks - d2.Ticks) / 10);

            return SendToWireshark(buffer, offset, lenght, date_sec, date_usec);
        }

        public bool SendToWireshark(byte[] buffer, int offset, int lenght, UInt32 date_sec, UInt32 date_usec)
        {
            if (IsConnected == false)
                return false;

            if (buffer == null) return false;
            if (buffer.Length < (offset + lenght)) return false;

            pcap_hdr_p pHdr = new pcap_hdr_p((UInt32)lenght, date_sec, date_usec);
            byte[] b = pHdr.ToByteArray();

            try
            {
                // Wireshark Header
                WiresharkPipe.Write(b, 0, b.Length);
                // Bacnet packet
                WiresharkPipe.Write(buffer, offset, lenght);
                WiresharkPipe.Flush();
            }
            catch (System.IO.IOException)
            {
                wiresharkbufferServer.Clear();
                wiresharkbufferClient.Clear();
                // broken pipe, try to restart
                IsConnected = false;
                WiresharkPipe.Close();
                WiresharkPipe.Dispose();
                Thread th = new Thread(PipeCreate);
                th.IsBackground = true;
                th.Start();
                return false;
            }
            catch (Exception)
            {
                // Unknow error, not due to the pipe
                // No need to restart it
                return false;
            }

            return true;
        }

    }
}
