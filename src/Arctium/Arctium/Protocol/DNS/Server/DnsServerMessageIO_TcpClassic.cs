using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using System.Net;
using System.Net.Sockets;

namespace Arctium.Protocol.DNS.Server
{
    internal class DnsServerMessageIO_TcpClassic : IDnsServerMessageIOAdapter
    {
        private CancellationToken serverStopCancellationToken;
        private Func<Message, Task<Message>> serverProcessMessage;
        private int port;
        private DnsSerialize serializer = new DnsSerialize();
        private Task task;

        public DnsServerMessageIO_TcpClassic(int port)
        {
            this.port = port;
        }

        public void Configure(Func<Message, Task<Message>> serverProcessMessage, CancellationToken serverStopCancellationToken)
        {
            this.serverStopCancellationToken = serverStopCancellationToken;
            this.serverProcessMessage = serverProcessMessage;
        }

        public void OnServerStart()
        {
            this.task = Task.Run(async () => await OnServerStart2());
        }

        public async Task OnServerStart2()
        {
            var tcpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            tcpSocket.Bind(new IPEndPoint(IPAddress.Any, port));
            tcpSocket.Listen(100);
            Socket client = null;
            BytesCursor clientBytes = null;

            while (!serverStopCancellationToken.IsCancellationRequested)
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

                    clientBytes = new BytesCursor(buffer.Buffer, 2, buffer.Length - 2);
                    var clientMsg = serializer.Decode(clientBytes);
                    var responseMessage = await serverProcessMessage(clientMsg);
                    var responseBuffer = new ByteBuffer();
                    serializer.Encode_ClassicTcp(responseMessage, responseBuffer);

                    // var test = serializer.Decode(new BytesCursor(responseBuffer.Buffer, 0, responseBuffer.Length), true);

                    client.Send(responseBuffer.Buffer, 0, responseBuffer.Length, SocketFlags.None);
                }
                catch (Exception e)
                {
                    // todo
                }
            }
        }

        public void OnServerStop()
        {
            throw new NotImplementedException();
        }
    }
}
