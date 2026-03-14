using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using System.Net;
using System.Net.Sockets;

namespace Arctium.Protocol.DNS.Server
{
    public class DnsServerImpl
    {
        DnsServerOptions options;
        DnsSerialize serializer = new DnsSerialize();

        public DnsServerImpl(DnsServerOptions options)
        {
            ValidateOptions(options);
            
            this.options = options;
        }

        private void ValidateOptions(DnsServerOptions options)
        {
            if (options.MessageIO == null) throw new ArgumentException("messageio null");
        }

        public void Start()
        {
            OnServerStartParams startParams = new OnServerStartParams(OnClientMessageReceived, options.StopServerCancellationTokenSource.Token);
            options.MessageIO.OnServerStart(startParams);
        }

        public void Stop()
        {
            options.StopServerCancellationTokenSource.Cancel();
            options.MessageIO.OnServerStop();
        }

        public void OnException(BytesCursor clientBytes, EndPoint udpClientEndpoint, Socket tcpClientSocket, Exception e)
        {
            // intentionally ignoring any other exceptions
            try
            {
                DnsException de = e as DnsException;
                Header clientHeader;
                Question clientQuestion;

                if (clientBytes == null || de == null || (int)de.ProtocolError >> 8 > 5)
                {
                    // silently drop packet, this errors must be ignored
                    return;
                }

                try
                {
                    // tcp only: skip 2 bytes because they are total msg len
                    clientBytes.CurrentOffset = tcpClientSocket != null ? 2 : 0; 
                    clientHeader = serializer.Decode_Header(clientBytes);
                    clientQuestion = serializer.Decode_Question(clientBytes);
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
                //serializer.EncodeClassic(errorResponseMsg, responseBytes);
                throw new NotImplementedException();
                if (udpClientEndpoint != null)
                {
                    //udpSocket.SendTo(responseBytes.Buffer, 0, responseBytes.Length, SocketFlags.None, udpClientEndpoint);
                }
                else
                {
                    tcpClientSocket.Send(responseBytes.Buffer, 0, responseBytes.Length, SocketFlags.None);
                }
            }
            catch (Exception ee)
            {
                // silently drop packet, something went wrong, ignore everything (e.g. socket error)
            }
        }

        async Task<Message> OnClientMessageReceived(Message clientMsg)
        {
            try
            {
                var result = await OnClientMessageReceived2(clientMsg);
                
                return result;
            }
            catch (Exception e)
            {
                //temp return internal error
                var errorResponseMsg = new Message();
                var h = new Header();

                h.ANCount = 0;
                h.ARCount = 0;
                h.NSCount = 0;
                h.QDCount = 1;
                h.AA = false;
                h.RA = false;
                h.RD = clientMsg.Header.RD;
                h.TC = false;
                h.Id = clientMsg.Header.Id;
                h.Opcode = clientMsg.Header.Opcode;
                h.QR = QRType.Response;
                h.RCode = ResponseCode.ServerFailure;

                errorResponseMsg.Header = h;
                errorResponseMsg.Question = clientMsg.Question;

                errorResponseMsg.Additional = null;
                errorResponseMsg.Answer = null;
                errorResponseMsg.Authority = null;

                return errorResponseMsg;
            }
        }

        async Task<Message> OnClientMessageReceived2(Message clientMsg)
        {
            // algorithm based on rfc1034, page 24 reference algorithm

            Header h = clientMsg.Header;
            Question q = clientMsg.Question[0];
            Message response = new Message();
            Header rheader = new Header();
            List<ResourceRecord> outAnswer = new List<ResourceRecord>(), outAuthority = new List<ResourceRecord>(), outAdditional = new List<ResourceRecord>();

            if (h.QR != QRType.Query) throw new DnsException(DnsProtocolError.QRTypeNotQuery);
            if (h.QDCount != 1) throw new DnsException(DnsProtocolError.QDCountNotEqual1);

            var algorithm = new DnsServerAlgorithm();
            await algorithm.Start(options, clientMsg);

            rheader.Id = h.Id;
            rheader.QR = QRType.Response;
            rheader.Opcode = h.Opcode;
            rheader.AA = algorithm.outAuthoritativeAnswer;
            rheader.TC = false;
            rheader.RD = h.RD;
            rheader.RA = options.RecursionAvailable;
            rheader.RCode = ResponseCode.NoErrorCondition;

            Question rquestion = new Question()
            {
                QClass = q.QClass,
                QName = q.QName,
                QType = q.QType
            };

            response.Header = rheader;
            response.Question = new Question[] { rquestion };
            response.Answer = algorithm.outAnswer.ToArray();
            response.Authority = algorithm.outAuthority.ToArray();
            response.Additional = algorithm.outAdditional.ToArray();
            
            rheader.QDCount = (ushort)(response.Question?.Length ?? 0);
            rheader.ANCount = (ushort)(response.Answer?.Length ?? 0);
            rheader.ARCount = (ushort)(response.Additional?.Length ?? 0);
            rheader.NSCount = (ushort)(response.Authority?.Length ?? 0);

            return response;
        }
    }

    class DnsServerCache() : IDnsServerRecordsData
    {
        public Task<DnsNode> GetAsync(string name, QClass qclass, QType type)
        {
            return Task.FromResult<DnsNode>(null);
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