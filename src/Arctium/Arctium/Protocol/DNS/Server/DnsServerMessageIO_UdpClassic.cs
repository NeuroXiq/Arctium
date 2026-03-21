using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using System.Net;
using System.Net.Sockets;

namespace Arctium.Protocol.DNS.Server
{
    public class DnsServerMessageIO_UdpClassic : IDnsServerMessageIOAdapter
    {
        private OnServerStartParams onServerStartParams;
        private DnsSerialize serializer = new DnsSerialize();
        private int port;
        private Task task;
        private Socket udpSocket;

        public DnsServerMessageIO_UdpClassic(int port)
        {
            this.port = port;
        }

        public void OnServerStart(OnServerStartParams onServerStartParams)
        {
            this.onServerStartParams = onServerStartParams;

            udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udpSocket.Bind(new IPEndPoint(IPAddress.Any, port));
            task = Task.Run(async () => await OnServerStart2(), onServerStartParams.ServerStopCancellationToken);
        }

        public async Task OnServerStart2()
        {
            EndPoint clientEndpoint = null;
            BytesCursor clientBytes = null;

            while (!this.onServerStartParams.ServerStopCancellationToken.IsCancellationRequested)
            {
                try
                {
                    clientEndpoint = null;
                    clientBytes = null;

                    byte[] buf = new byte[512];

                    clientEndpoint = new IPEndPoint(IPAddress.Any, 0);

                    var recvResult = await udpSocket.ReceiveFromAsync(buf, clientEndpoint, onServerStartParams.ServerStopCancellationToken);
                    int recvLen = recvResult.ReceivedBytes;
                    clientEndpoint = recvResult.RemoteEndPoint;

                    clientBytes = new BytesCursor(buf, 0, recvLen);
                    var clientMsg = serializer.Decode(clientBytes);

                    var dnsContext = new DnsRequestContext(clientMsg);
                    this.onServerStartParams.Next.Next(dnsContext).Wait();
                    var res = dnsContext.ServerMessage;
                    var responseBytes = new ByteBuffer();
                    serializer.EncodeRaw(res, responseBytes);

                    if (responseBytes.Length > DnsConsts.UdpSizeLimit)
                    {
                        res = ConvertToTrunCated(res);
                        responseBytes.Reset();
                        serializer.Encode_ClassicUdp(res, responseBytes);
                    }

                    udpSocket.SendTo(responseBytes.Buffer, 0, responseBytes.Length, SocketFlags.None, clientEndpoint);
                }
                catch (OperationCanceledException e) { }
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
            udpSocket.Close();
        }
    }
}
