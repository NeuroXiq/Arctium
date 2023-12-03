using Arctium.Shared.Helpers.Buffers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1
{
    public abstract class DgramIO
    {
        public virtual int ReadDgram(byte[] outBuf, int offset) { return ReadDgramAsync(outBuf, offset).Result; }
        public virtual void WriteDgram(byte[] buffer, int offset, int length) { WriteDgram(buffer, offset, length); }

        public abstract void Close();

        public abstract Task<int> ReadDgramAsync(byte[] outBuf, int outOffs);
        public abstract Task WriteDgramAsync(byte[] buffer, int offset, int length);
    }

    class UdpSocketClient : DgramIO
    {
        public EndPoint ClientEndpoint;
        public ByteBuffer byteBuffer;
        private QuicSocketServer parentServer;
        private object _lock = new object();


        public UdpSocketClient(QuicSocketServer parentServer)
        {
            this.parentServer = parentServer;
        }

        public override void Close()
        {
            throw new NotImplementedException();
        }

        public override async Task<int> ReadDgramAsync(byte[] buffer, int offset)
        {
            if (byteBuffer.DataLength == 0)
            {
                await parentServer.ReadDgram(this);
            }

            int dataLen = byteBuffer.DataLength;

            if (dataLen > 0)
            {
                MemCpy.Copy(byteBuffer.Buffer, 0, buffer, offset, dataLen);
                byteBuffer.TrimStart(dataLen);
            }

            return dataLen;
        }

        public void ThreadSafeWriteDgram(byte[] buffer, int offset, int length)
        {
            lock (_lock)
            {
                byteBuffer.Append(buffer, offset, length);
            }
        }

        public override async Task WriteDgramAsync(byte[] buffer, int offset, int length)
        {
            await parentServer.WriteDgram(buffer, offset, length, ClientEndpoint);
        }
    }

    public class QuicSocketServer
    {
        private Socket socket;
        private Dictionary<string, UdpSocketClient> connectedClients = new Dictionary<string, UdpSocketClient>();

        public QuicSocketServer(IPAddress bindSocketIPAddr, int socketBindPort)
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(bindSocketIPAddr, socketBindPort));
        }

        internal async Task ReadDgram(UdpSocketClient client)
        {
            // todo do this in objectpool (avoid multiple allocs)
            Memory<byte> buffer = new Memory<byte>(new byte[16 * 1024]);
            var result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, client.ClientEndpoint);

            client.ThreadSafeWriteDgram(buffer.ToArray(), 0, result.ReceivedBytes);
        }

        public async Task WriteDgram(byte[] buf, int offs, int len, EndPoint endpoint)
        {
            
        }

        public object Accept()
        {
            return null;
        }

        public async Task<object> AcceptAsync(CancellationToken cancellationToken = default)
        {
            while (true)
            {
                var sender = new IPEndPoint(IPAddress.Any, 0) as EndPoint;

                // todo do this in objectpool (avoid multiple allocs)
                Memory<byte> buffer = new Memory<byte>(new byte[16 * 1024]);
                var result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, sender, cancellationToken);
                var clientId = result.RemoteEndPoint.ToString();
                UdpSocketClient client = null;
                bool exists = connectedClients.TryGetValue(clientId, out client);
                
                if (!exists)
                {
                    client = new UdpSocketClient(this)
                    {
                        byteBuffer = new ByteBuffer(),
                        ClientEndpoint = result.RemoteEndPoint
                    };
                }

                client.ThreadSafeWriteDgram(buffer.ToArray(), 0, result.ReceivedBytes);

                // if client already exists do nothing and wait for other
                // in meantime if client already exists just appent received bytes to 
                // existing client
                if (!exists)
                {
                    var stream = new QuicSrvStream(client);
                    stream.AcceptClientAsync();

                    return stream;
                }
            }
        }
    }
}
