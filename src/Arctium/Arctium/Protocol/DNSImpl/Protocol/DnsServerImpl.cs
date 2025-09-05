using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Model;
using Arctium.Shared;
using System;
using System.Collections.Generic;
using System.Diagnostics;
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

        Socket tcpSocket;
        Socket udpSocket;

        public DnsServerImpl(DnsServerOptions options)
        {
            this.options = options;
        }

        public void Stop()
        {
            tcpSocket?.Dispose();
            udpSocket?.Dispose();
        }

        public void StartTcp()
        {
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            s.Bind(new IPEndPoint(IPAddress.Any, options.PortTcp));

            s.Listen(100);

            while (!options.CancellationToken.IsCancellationRequested)
            {
                var client = s.Accept();
                byte[] lenBuffer = new byte[2];

                int received = client.Receive(lenBuffer, 0, 2, SocketFlags.None);

                if (received == 0) throw new DnsException(DnsProtocolError.ReceivedZeroBytesFromClient);
                if (received == 1)
                {
                    received = client.Receive(lenBuffer, 1, 1, SocketFlags.None);
                    if (received == 0) throw new DnsException(DnsProtocolError.ReceivedZeroBytesFromClient);
                }

                int toReceive = MemMap.ToUShort2BytesBE(lenBuffer, 0);
                ByteBuffer buffer = new ByteBuffer();
                buffer.AllocEnd(toReceive);
                int offset = 0;

                while (toReceive > 0)
                {
                    received = client.Receive(buffer.Buffer, offset, toReceive, SocketFlags.None);
                    offset += received;
                    toReceive -= received;
                }

                var clientMessage = serializer.Decode(new BytesSpan(buffer.Buffer, 0, buffer.DataLength));
                var res = GetResponseMessage(clientMessage);
                var responseBytes = SerializeResponseMessage(res);

                if (responseBytes.DataLength > ushort.MaxValue)
                    throw new DnsException(DnsOtherError.SerializeResponseMessageTcpExceedUShortMaxValue);

                // first send ushort 2-bytes with message length
                MemMap.ToBytes1UShortBE((ushort)responseBytes.DataLength, lenBuffer, 0);
                client.Send(lenBuffer, 0, 2, SocketFlags.None);
                
                // now send data
                client.Send(responseBytes.Buffer, 0, responseBytes.DataLength, SocketFlags.None);
            }
        }

        public void StartUdp()
        {
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            s.Bind(new IPEndPoint(IPAddress.Any, options.PortUdp));

            while (!options.CancellationToken.IsCancellationRequested)
            {
                try
                {
                    Process(s).Wait(options.CancellationToken);
                }
                catch (Exception e)
                {

                    throw;
                }

                // var result = new BytesSpan(a, 0, a.Length);

                //s.SendTo(bytes.Buffer, remoteEndpoint);
                //MemDump.HexDump(buf, 0, recvLen, chunkLength: 1);
            }
        }

        public async Task Process(Socket serverSocket)
        {
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

            if (responseBytes.DataLength > DnsConsts.UdpSizeLimit)
            {
                res = ConvertToTrunCated(res);
                responseBytes = SerializeResponseMessage(res);
            }

            serverSocket.SendTo(responseBytes.Buffer, 0, responseBytes.DataLength, SocketFlags.None, clientEndpoint);
        }

        ByteBuffer SerializeResponseMessage(Message response)
        {
            var rbytes = new ByteBuffer();
            serializer.Encode(response, rbytes);

            return rbytes;
        }

        Message ConvertToTrunCated(Message responseMessage)
        {
            responseMessage.Header.TC = true;

            responseMessage.Additional = null;
            responseMessage.Answer = null;
            responseMessage.Authority = null;

            responseMessage.Header.ANCount = 0;
            responseMessage.Header.NSCount = 0;
            responseMessage.Header.ARCount = 0;

            return responseMessage;
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
            
            // test
            // response.Additional = result;
            // response.Authority = result;

            rheader.QDCount = (ushort)response.Question.Length;
            rheader.ANCount = (ushort)response.Answer.Length;
            rheader.ARCount = (ushort)(response.Additional?.Length ?? 0);
            rheader.NSCount = (ushort)(response.Authority?.Length ?? 0);

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