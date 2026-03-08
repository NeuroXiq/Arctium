using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using System.Net;
using System.Net.Sockets;

namespace Arctium.Protocol.DNS.Server
{
    public class DnsServerMessageIO_UdpClassic : IDnsServerMessageIOAdapter
    {
        private Func<Message, Task<Message>> processMessage;
        private CancellationToken serverStopCancellationToken;
        private DnsSerialize serializer = new DnsSerialize();
        private int port;
        private Task task;

        public DnsServerMessageIO_UdpClassic(int port)
        {
            this.port = port;
        }

        public void Configure(
            Func<Message, Task<Message>> serverProcessMessage,
            CancellationToken serverStopCancellationToken)
        {
            this.processMessage = serverProcessMessage;
            this.serverStopCancellationToken = serverStopCancellationToken;
        }

        public void OnServerStart()
        {
            this.task = Task.Run(async () => await OnServerStart2());
        }

        public async Task OnServerStart2()
        {
            var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udpSocket.Bind(new IPEndPoint(IPAddress.Any, port));
            EndPoint clientEndpoint = null;
            BytesCursor clientBytes = null;

            while (!serverStopCancellationToken.IsCancellationRequested)
            {
                try
                {
                    clientEndpoint = null;
                    clientBytes = null;

                    byte[] buf = new byte[512];

                    clientEndpoint = new IPEndPoint(IPAddress.Any, 0);

                    var recvResult = await udpSocket.ReceiveFromAsync(buf, clientEndpoint);
                    int recvLen = recvResult.ReceivedBytes;
                    clientEndpoint = recvResult.RemoteEndPoint;

                    clientBytes = new BytesCursor(buf, 0, recvLen);
                    var clientMsg = serializer.Decode(clientBytes);

                    var res = processMessage(clientMsg).Result;
                    var responseBytes = new ByteBuffer();
                    serializer.EncodeClassic(res, responseBytes);

                    if (responseBytes.Length > DnsConsts.UdpSizeLimit)
                    {
                        res = ConvertToTrunCated(res);
                        responseBytes.Reset();
                        serializer.EncodeClassic(res, responseBytes);
                    }

                    udpSocket.SendTo(responseBytes.Buffer, 0, responseBytes.Length, SocketFlags.None, clientEndpoint);
                }
                catch (Exception e)
                {
                    // fatal exception
                    // todo return message protocol error
                }
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

        public void OnServerStop()
        {
            throw new NotImplementedException();
        }
    }
}
