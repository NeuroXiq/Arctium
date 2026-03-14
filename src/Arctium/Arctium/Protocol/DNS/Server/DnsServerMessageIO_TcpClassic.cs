using Arctium.Protocol.DNS.Model;
using Arctium.Protocol.DNS.Protocol;
using Arctium.Shared;
using System.Net;
using System.Net.Sockets;

/*
 * https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.socketasynceventargs?view=net-10.0
 * SocketAsyncEventArgs
 */

namespace Arctium.Protocol.DNS.Server
{
    internal class DnsServerMessageIO_TcpClassic : IDnsServerMessageIOAdapter
    {
        private CancellationToken serverStopCancellationToken;
        private int port;
        private int receiveTimeoutMs;
        private int listedBacklog;
        private DnsSerialize serializer = new DnsSerialize();
        private Task task;
        private OnServerStartParams onServerStartParams;
        private Socket tcpSocket;

        public DnsServerMessageIO_TcpClassic(int port, int receiveTimeoutMs, int listedBacklog)
        {
            this.port = port;
            this.receiveTimeoutMs = receiveTimeoutMs;
            this.listedBacklog = listedBacklog;
        }

        public void OnServerStart(OnServerStartParams onServerStartParams)
        {
            this.onServerStartParams = onServerStartParams;

            tcpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            tcpSocket.Bind(new IPEndPoint(IPAddress.Any, port));
            tcpSocket.Listen(listedBacklog);

            task = Task.Run(async () => await OnServerStart2());
        }

        public async Task OnServerStart2()
        {
            while (!serverStopCancellationToken.IsCancellationRequested)
            {
                try
                {
                    var client = await tcpSocket.AcceptAsync();
                    var q = Task.Run(async () => await ProcessAcceptedSocketClient(client));
                    q.Wait();
                }
                catch (Exception e)
                {
                    // todo
                }
            }
        }

        public void OnServerStop()
        {
            tcpSocket.Close();
        }

        private async Task ProcessAcceptedSocketClient(Socket client)
        {
            try
            {
                int offset = 0;
                int received = 0;
                int toReceive = 2;
                var buffer = new ByteBuffer();
                buffer.AllocEnd(2);

                var q = new CancellationTokenSource();
                
                var cancelToken = CancellationTokenSource.CreateLinkedTokenSource(serverStopCancellationToken);
                cancelToken.CancelAfter(receiveTimeoutMs);

                while (toReceive > 0)
                {
                    cancelToken.Token.ThrowIfCancellationRequested();

                    received = await client.ReceiveAsync(
                        new ArraySegment<byte>(buffer.Buffer, offset, toReceive),
                        cancelToken.Token);

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

                var clientBytes = new BytesCursor(buffer.Buffer, 2, buffer.Length - 2);
                var clientMsg = serializer.Decode(clientBytes);
                var responseMessage = await onServerStartParams.ProcessMessageAsync(clientMsg);
                var responseBuffer = new ByteBuffer();
                serializer.Encode_ClassicTcp(responseMessage, responseBuffer);

                // var test = serializer.Decode(new BytesCursor(responseBuffer.Buffer, 0, responseBuffer.Length), true);

                client.Send(responseBuffer.Buffer, 0, responseBuffer.Length, SocketFlags.None);
            }
            catch (Exception e)
            {
                try
                {
                    client.Close();
                }
                catch 
                {
                }
            }
        }
    }
}
