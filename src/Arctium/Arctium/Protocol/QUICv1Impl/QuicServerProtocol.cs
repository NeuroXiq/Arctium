using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Helpers.DataStructures;
using Arctium.Protocol.QUICv1;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Arctium.Protocol.QUICv1Impl
{
    // todo is using properies/fields safe when using async/await? race condition
    internal class QuicServerProtocol
    {
        private DgramIO dgramio;
        private ByteBuffer packets = new ByteBuffer();
        private byte[] updReadBuffer = new byte[16 * 1024];

        QuicModelCoding coding = new QuicModelCoding();

        List<QuicConnection> connections = new List<QuicConnection>();

        public QuicServerProtocol(DgramIO dgramio)
        {
            this.dgramio = dgramio;
        }

        public async Task ListenForConnectionAsync()
        {
            await LoadPacket();
        }

        bool isLongPacket = true;

        public async Task WritePacket(byte[] buffer, int offset, int length)
        {
            await dgramio.WriteDgramAsync(buffer, offset, length);
        }

        public async Task LoadPacket()
        {
            if (packets.DataLength == 0)
            {
                int datalen = 0;

                for (int i = 0; i < 50 && datalen == 0; i++)
                {
                    datalen = await dgramio.ReadDgramAsync(updReadBuffer, 0);
                    Thread.Sleep(100);
                }
                packets.Append(updReadBuffer, 0, datalen);
            }

            if (packets.DataLength == 0) throw new Exception("protocol error: timeout read");
            byte[] drams = packets.Buffer;

            if (QuicModelCoding.IsLongHeaderPacket(drams))
            {
                var lhp = QuicModelCoding.DecodeLHP(drams, 0, true);

                QuicConnection connection = null;

                for (int i = 0; i < connections.Count; i++)
                {
                    var current = connections[i].ServerConnectionId;
                    if (MemOps.Memcmp(lhp.DestConId.Span, new Span<byte>(current, 0, current.Length)))
                    {
                        connection = connections[i];
                        break;
                    }
                }

                bool isnew = false;

                if (connection == null)
                {
                    connection = new QuicConnection(this, EndpointType.Server);
                    isnew = true;
                }

                connection.BufferPacket(drams, 0, lhp.A_TotalPacketLength);
                packets.TrimStart(lhp.A_TotalPacketLength);

                if (isnew)
                {
                    connections.Add(connection);
                    await connection.AcceptClient();
                }
            }
            else throw new NotImplementedException();

            // buffer.Append(readDgramBuf, 0, datalen);

        }

        private async Task LoadDgram()
        {
            
        }
    }
}
