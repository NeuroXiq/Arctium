using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Model;
using Arctium.Shared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Protocol
{
    public class DnsServerImpl
    {
        public DnsServerImpl(DnsServerOptions options)
        {
            
        }

        DnsSerialize serializer = new DnsSerialize();

        public void Start()
        {
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            var bindEndpoint = new IPEndPoint(IPAddress.Any, 53);


            s.Bind(bindEndpoint);

            byte[] buf = new byte[12345 ];
            /*
             4F CC 01 00
             00 01 00 00
             00 00 00 00
             04 61 73 64
             66 03 63 6F
             6D 00 00 01
             00 01
             */

            byte[] a = new byte[]
            {
                0x4F, 0xCC, 0x01, 0x00,
                0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x04, 0x61, 0x73, 0x64,
                0x66, 0x03, 0x63, 0x6F,
                0x6D, 0x00, 0x00, 0x01,
                0x00, 0x01,
            };

            while (true)
            {
                EndPoint remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
                // int recvLen = s.ReceiveFrom(buf, ref remoteEndpoint);
                //var result = new BytesSpan(buf, 0, recvLen);
                var result = new BytesSpan(a, 0, a.Length);
                Process(result);

                //MemDump.HexDump(buf, 0, recvLen, chunkLength: 1);
            }
        }

        async Task Process(BytesSpan packet)
        {
            Message result = serializer.Decode(packet);

            Header h = result.Header;

            if (h.QR != QRType.Query) throw new DnsException(DnsProtocolError.QRTypeNotQuery);
            if (h.QDCount != 1) throw new DnsException(DnsProtocolError.QDCountNotEqual1);

            Question q = result.Question[0];

            Message response = new Message();
            Header rheader = new Header();

            rheader.Id = 0;
            rheader.QR = QRType.Response;
            rheader.Opcode = Opcode.Query;
            rheader.AA = false;
            rheader.TC = false;
            rheader.RD = false;
            rheader.RA = false;
            rheader.RCode = ResponseCode.NoErrorCondition;
            
            rheader.QDCount = 1;
            rheader.ANCount = 1;
            rheader.NSCount = 0;
            rheader.ARCount = 0;

            Question rquestion = new Question()
            {
                QClass = q.QClass,
                QName = q.QName,
                QType = q.QType
            };

            ResourceRecord answer1 = new ResourceRecord()
            {
                Class = QClass.IN,
                Name = "www",
                Type = QType.A,
                TTL = 300,
                RDLength = 0,
                RData = new RDataA()
                {
                    Address = 0xffeebbcc
                }
            };

            ResourceRecord answer2 = new ResourceRecord()
            {
                Class = QClass.IN,
                Name = "www",
                Type = QType.A,
                TTL = 400,
                RDLength = 0,
                RData = new RDataA()
                {
                    Address = 0xaabbccdd
                }
            };

            response.Header = rheader;
            response.Question = new Question[] { rquestion };
            response.Answer = new ResourceRecord[] { answer1, answer2 };

            var rbytes = new ByteBuffer();
            serializer.Encode(response, rbytes);
        }

        /*
         SocketAsyncEventArgs args = new SocketAsyncEventArgs();
            args.Completed += OnReceive;
            args.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);


            while (s.ReceiveFromAsync(args))
            {
                
            }
         */
    }
}

/*
 warning:
 using nested onreceive calls, if all are synchronous, the can stackoverflow




 using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

class UdpAsyncServer
{
    static Socket udpSocket;

    static void Main()
    {
        udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(IPAddress.Any, 11000));

        Console.WriteLine("UDP Server listening on port 11000...");

        StartReceiving();

        Console.ReadLine(); // Keep the app running
    }

    static void StartReceiving()
    {
        SocketAsyncEventArgs args = new SocketAsyncEventArgs();
        args.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
        args.SetBuffer(new byte[1024], 0, 1024);
        args.Completed += OnReceive;

        if (!udpSocket.ReceiveFromAsync(args))
        {
            // If operation completed synchronously, handle immediately
            OnReceive(null, args);
        }
    }

    static void OnReceive(object sender, SocketAsyncEventArgs args)
    {
        if (args.SocketError == SocketError.Success)
        {
            string receivedText = Encoding.UTF8.GetString(args.Buffer, 0, args.BytesTransferred);
            Console.WriteLine($"Received from {args.RemoteEndPoint}: {receivedText}");
        }
        else
        {
            Console.WriteLine($"Socket error: {args.SocketError}");
        }

        // Reuse the same args object for next receive
        args.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
        if (!udpSocket.ReceiveFromAsync(args))
        {
            OnReceive(null, args);
        }
    }
}
 */