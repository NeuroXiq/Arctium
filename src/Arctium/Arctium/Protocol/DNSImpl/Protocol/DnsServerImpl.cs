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
        DnsServerOptions options;
        DnsSerialize serializer = new DnsSerialize();

        public DnsServerImpl(DnsServerOptions options)
        {
            this.options = options;
        }

        public void Start(CancellationToken cancellationToken)
        {
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            s.Bind(new IPEndPoint(IPAddress.Any, options.SocketBindPort));

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    Process(s).Wait(cancellationToken);
                }
                catch (Exception e)
                {

                    throw;
                }
                

                // var result = new BytesSpan(a, 0, a.Length);

                //s.SendTo(bytes.Buffer, remoteEndpoint);
                Console.WriteLine("asdf");
                //MemDump.HexDump(buf, 0, recvLen, chunkLength: 1);
            }
        }

        public async Task Process(Socket serverSocket)
        {
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

            byte[] buf = new byte[12345];

            EndPoint clientEndpoint = new IPEndPoint(IPAddress.Any, 0);

            //int recvLen = await serverSocket.ReceiveFrom(buf, ref clientEndpoint);
            var recvResult = await serverSocket.ReceiveFromAsync(buf, clientEndpoint);
            int recvLen = recvResult.ReceivedBytes;
            clientEndpoint = recvResult.RemoteEndPoint;

            var clientBytes = new BytesSpan(buf, 0, recvLen);
            Message clientMsg = serializer.Decode(clientBytes);

            var res = GetResponseMessage(clientMsg);
            var responseBytes = SerializeResponseMessage(res);

            serverSocket.SendTo(responseBytes.Buffer, 0, responseBytes.DataLength, SocketFlags.None, clientEndpoint);
        }

        ByteBuffer SerializeResponseMessage(Message response)
        {
            var rbytes = new ByteBuffer();
            serializer.Encode(response, rbytes);

            return rbytes;
        }

        Message GetResponseMessage(Message clientMsg)
        {
            Header h = clientMsg.Header;

            if (h.QR != QRType.Query) throw new DnsException(DnsProtocolError.QRTypeNotQuery);
            if (h.QDCount != 1) throw new DnsException(DnsProtocolError.QDCountNotEqual1);

            Question q = clientMsg.Question[0];

            Message response = new Message();
            Header rheader = new Header();

            rheader.Id = h.Id;
            rheader.QR = QRType.Response;
            rheader.Opcode = h.Opcode;
            rheader.AA = true;
            rheader.TC = false;
            rheader.RD = h.RD;
            rheader.RA = false;
            rheader.RCode = ResponseCode.NoErrorCondition;
            rheader.NSCount = 0;
            rheader.ARCount = 0;

            var result = options.DnsServerDataSource.GetRRsAsync(clientMsg.Question[0]).Result;

            // if (result.Length == 0) throw new NotImplementedException("todo");

            Question rquestion = new Question()
            {
                QClass = q.QClass,
                QName = q.QName,
                QType = q.QType
            };

            response.Header = rheader;
            response.Question = new Question[] { rquestion };
            response.Answer = result;

            rheader.QDCount = (ushort)response.Question.Length;
            rheader.ANCount = (ushort)response.Answer.Length;

            return response;
        }

        
    }
}

/*
         SocketAsyncEventArgs args = new SocketAsyncEventArgs();
            args.Completed += OnReceive;
            args.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);


            while (s.ReceiveFromAsync(args))
            {
                
            }
*/

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