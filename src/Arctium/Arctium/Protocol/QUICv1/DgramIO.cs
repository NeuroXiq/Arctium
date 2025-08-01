﻿using Arctium.Shared.Helpers.Buffers;
using Arctium.Protocol.QUICv1Impl;
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

namespace Arctium.Protocol.QUICv1
{
    public abstract class DgramIO
    {
        // public virtual int ReadDgram(byte[] outBuf, int offset) { return ReadDgramAsync(outBuf, offset).Result; }
        // public virtual void WriteDgram(byte[] buffer, int offset, int length) { WriteDgram(buffer, offset, length); }

        public abstract void Close();

        public abstract Task<int> ReadDgramAsync(byte[] outBuf, int outOffs);
        public abstract Task WriteDgramAsync(byte[] buffer, int offset, int length);
    }

    class UdpSocketClient : DgramIO
    {
        public EndPoint ClientEndpoint;
        // public ByteBuffer byteBuffer;
        Queue<byte[]> dgrams = new Queue<byte[]>();
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
            if (dgrams.Count == 0)
            {
                await parentServer.ReadDgram(this);
            }

            if (dgrams.Count == 0) throw new Exception("timeout read waiting");

            lock (_lock)
            {
                var d = dgrams.Dequeue();
                MemCpy.Copy(d, 0, buffer, offset, d.Length);

                return d.Length;
            }
        }

        public void ThreadSafeWriteDgram(byte[] buffer, int offset, int length)
        {
            lock (_lock)
            {
                var dgramToPush = MemCpy.CopyToNewArray(buffer, offset, length);
                dgrams.Enqueue(dgramToPush);
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
        private EndPoint endpointAny = new IPEndPoint(IPAddress.Any, 0) as EndPoint;

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
            socket.SendTo(new ArraySegment<byte>(buf, offs, len), SocketFlags.None, endpoint);
            // socket.SendTo(new ArraySegment<byte>(buf, offs, len), SocketFlags.None, (new IPEndPoint(IPAddress.Loopback, 12345)) as EndPoint);
        }

        public object Accept()
        {
            return null;
        }

        QuicServerProtocol quicSrvProtocol;

        public struct ProcessNextUdpResult
        {
            public object Connection;
        }

        public async Task<object> ProcessNextUdp(CancellationToken cancellationToken = default)
        {
            // todo do this in objectpool (avoid multiple allocs), or maybe Span<byte>
            Memory<byte> buffer = new Memory<byte>(new byte[65535]);
            var result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, endpointAny, cancellationToken);

            var clientId = result.RemoteEndPoint.ToString();

            UdpSocketClient client = null;
            bool exists = connectedClients.TryGetValue(clientId, out client);

            if (!exists)
            {
                client = new UdpSocketClient(this)
                {
                    ClientEndpoint = result.RemoteEndPoint
                };
            }

            client.ThreadSafeWriteDgram(buffer.ToArray(), 0, result.ReceivedBytes);

            // if client already exists do nothing and wait for other
            // in meantime if client already exists just append received bytes to 
            // existing client
            if (!exists)
            {
                quicSrvProtocol = new QuicServerProtocol(client);
                await quicSrvProtocol.ListenForConnectionAsync();

                throw new NotImplementedException();
            }

            return null;
        }
    }
}
