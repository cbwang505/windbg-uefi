using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace pipe
{
    class PacketWriter
    {
        private CaptureFileWriterDevice outdev = null;

        public static PacketWriter Current = new PacketWriter();
        public PacketWriter()
        {
            string exepathdir = System.IO.Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

            string pacpfilepath = System.IO.Path.Combine(exepathdir, "windbg-" + DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss") + ".pcap");

            outdev = new CaptureFileWriterDevice(pacpfilepath);
            outdev.Open();
        }


        public byte[] WritePactet(byte[] buffer, bool fromhost)
        {
            EthernetPacket eth = null;
            IPv4Packet ip = null;
            UdpPacket udp = null;
            ushort PortClient = 51111;
            ushort PortServer = 51112;
            var LocalIp = IPAddress.Parse("192.168.0.1");
            var fakeIp = IPAddress.Parse("192.168.0.2");
            PhysicalAddress fakeMac = PhysicalAddress.Parse("001122334455");
            PhysicalAddress BroadcastMac = PhysicalAddress.Parse("FFFFFFFFFFFF");
            if (fromhost)
            {
                eth = new EthernetPacket(fakeMac, BroadcastMac, EthernetType.IPv4);
                ip = new IPv4Packet(fakeIp, LocalIp);
                udp = new UdpPacket(PortClient, PortServer);
            }
            else
            {
                eth = new EthernetPacket( BroadcastMac, fakeMac, EthernetType.IPv4);
                ip = new IPv4Packet(LocalIp,fakeIp);
                udp = new UdpPacket(PortServer,PortClient );
            }

            eth.PayloadPacket = ip;
            ip.PayloadPacket = udp;
            udp.PayloadData = buffer;
            udp.UpdateCalculatedValues();
            ip.UpdateCalculatedValues();
            udp.UpdateUdpChecksum();
            ip.UpdateIPChecksum();
            outdev.Write(new ReadOnlySpan<byte>(eth.Bytes));
            return eth.Bytes;
        }
    }
}
