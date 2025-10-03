using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Model;
using Arctium.Shared;
using System.Net;
using System.Net.Sockets;

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
            tcpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            tcpSocket.Bind(new IPEndPoint(IPAddress.Any, options.PortTcp));
            tcpSocket.Listen(100);
            Socket client = null;
            BytesSpan clientBytes = null;

            while (!options.CancellationToken.IsCancellationRequested)
            {
                clientBytes = null;
                client = null;

                try
                {
                    client = tcpSocket.Accept();

                    int offset = 0;
                    int received = 0;
                    int toReceive = 2;
                    var buffer = new ByteBuffer();
                    buffer.AllocEnd(2);

                    while (toReceive > 0)
                    {
                        received = client.Receive(buffer.Buffer, offset, toReceive, SocketFlags.None);
                        offset += received;
                        toReceive -= received;

                        if (received == 0) throw new DnsException(DnsProtocolError.ReceivedZeroBytesButExpectedMoreTcp);
                        
                        // this 'if' executes only once - loaded first two bytes with msg length
                        if (offset == 2)
                        {
                            // first two bytes are msg length (tcp only)
                            toReceive = MemMap.ToUShort2BytesBE(buffer.Buffer, 0);
                            buffer.AllocEnd(toReceive);
                        }
                    }

                    clientBytes = new BytesSpan(buffer.Buffer, 2, buffer.DataLength);
                    var clientMsg = serializer.Decode(clientBytes);
                    var responseMessage = GetResponseMessage(clientMsg);
                    var responseBuffer = new ByteBuffer();
                    responseBuffer.AllocEnd(2);
                    serializer.Encode(responseMessage, responseBuffer);

                    if (responseBuffer.DataLength > ushort.MaxValue)
                        throw new DnsException(DnsProtocolError.EncodeResponseMessageTcpExceedUShortMaxValue);

                    // first 2-bytes are msg length
                    MemMap.ToBytes1UShortBE((ushort)(responseBuffer.DataLength - 2), responseBuffer.Buffer, 0);
                    client.Send(responseBuffer.Buffer, 0, responseBuffer.DataLength, SocketFlags.None);
                }
                catch (Exception e)
                {
                    OnException(clientBytes, null, client, e);
                }
            }
        }

        public void StartUdp()
        {
            udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udpSocket.Bind(new IPEndPoint(IPAddress.Any, options.PortUdp));
            EndPoint clientEndpoint = null;
            BytesSpan clientBytes = null;

            while (!options.CancellationToken.IsCancellationRequested)
            {
                try
                {
                    clientEndpoint = null;
                    clientBytes = null;

                    byte[] buf = new byte[512];

                    clientEndpoint = new IPEndPoint(IPAddress.Any, 0);

                    var recvResult = udpSocket.ReceiveFromAsync(buf, clientEndpoint).Result;
                    int recvLen = recvResult.ReceivedBytes;
                    clientEndpoint = recvResult.RemoteEndPoint;

                    clientBytes = new BytesSpan(buf, 0, recvLen);
                    var clientMsg = serializer.Decode(clientBytes);

                    var res = GetResponseMessage(clientMsg);
                    var responseBytes = new ByteBuffer();
                    serializer.Encode(res, responseBytes);

                    if (responseBytes.DataLength > DnsConsts.UdpSizeLimit)
                    {
                        res = ConvertToTrunCated(res);
                        responseBytes.Reset();
                        serializer.Encode(res, responseBytes);
                    }

                    udpSocket.SendTo(responseBytes.Buffer, 0, responseBytes.DataLength, SocketFlags.None, clientEndpoint);
                }
                catch (Exception e)
                {
                    OnException(clientBytes, clientEndpoint, null, e);
                }
            }
        }

        public void OnException(BytesSpan clientBytes, EndPoint udpClientEndpoint, Socket tcpClientSocket, Exception e)
        {
            // intentionally ignoring any other exceptions
            try
            {
                DnsException de = e as DnsException;
                Header clientHeader;
                Question clientQuestion;

                if (clientBytes == null || de == null || ((int)de.ProtocolError >> 8) > 5)
                {
                    // silently drop packet, this errors must be ignored
                    return;
                }

                try
                {
                    // tcp only: skip 2 bytes because they are total msg len
                    clientBytes.Offset = tcpClientSocket != null ? 2 : 0; 
                    clientHeader = serializer.Decode_Header(clientBytes, out int decodedLen);
                    clientBytes.ShiftOffset(decodedLen);
                    clientQuestion = serializer.Decode_Question(clientBytes, out _);
                }
                catch
                {
                    // silently drop packet, cannot parse header (thus create response header)
                    return;
                }

                var errorResponseMsg = new Message();
                var h = new Header();

                h.ANCount = 0;
                h.ARCount = 0;
                h.NSCount = 0;
                h.QDCount = 1;
                h.AA = false;
                h.RA = false;
                h.RD = clientHeader.RD;
                h.TC = false;
                h.Id = clientHeader.Id;
                h.Opcode = clientHeader.Opcode;
                h.QR = QRType.Response;
                h.RCode = (ResponseCode)((int)de.ProtocolError >> 8);

                errorResponseMsg.Header = h;
                errorResponseMsg.Question = new[] { clientQuestion };

                errorResponseMsg.Additional = null;
                errorResponseMsg.Answer = null;
                errorResponseMsg.Authority = null;

                ByteBuffer responseBytes = new ByteBuffer();
                serializer.Encode(errorResponseMsg, responseBytes);

                if (udpClientEndpoint != null)
                {
                    udpSocket.SendTo(responseBytes.Buffer, 0, responseBytes.DataLength, SocketFlags.None, udpClientEndpoint);
                }
                else
                {
                    tcpClientSocket.Send(responseBytes.Buffer, 0, responseBytes.DataLength, SocketFlags.None);
                }
            }
            catch (Exception ee)
            {
                // silently drop packet, something went wrong, ignore everything (e.g. socket error)
            }
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
            rheader.RA = options.RecursionAvailable;
            rheader.RCode = ResponseCode.NoErrorCondition;
            rheader.NSCount = 0;
            rheader.ARCount = 0;

            ResourceRecord[] answer = null, authority = null, additional = null;

            if (options.RecursionAvailable)
            {
                answer = options.RecursionService.ResolveAsync(clientMsg).Result;
            }
            else
            {
                answer = options.DnsServerDataSource.GetRRsAsync(clientMsg.Question[0]).Result;
            }

            Question rquestion = new Question()
            {
                QClass = q.QClass,
                QName = q.QName,
                QType = q.QType
            };

            response.Header = rheader;
            response.Question = new Question[] { rquestion };
            response.Answer = answer;
            response.Authority = authority;
            response.Additional = additional;
            
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