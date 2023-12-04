using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Helpers.DataStructures;
using Arctium.Standards.Connection.QUICv1;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    // todo is using properies/fields safe when using async/await? race condition
    internal class QuicServerProtocol
    {
        private DgramIO dgramio;
        private ByteBuffer buffer;
        
        QuicModelCoding coding = new QuicModelCoding();

        class BufferedPacket
        {
            public int Offset;
        }

        struct BufPkt
        {
            public int Offset;
        }

        List<QuicConnection> connections = new List<QuicConnection>();

        public QuicServerProtocol(DgramIO dgramio)
        {
            this.buffer = new ByteBuffer();
            this.dgramio = dgramio;
        }

        public async Task ListenForConnectionAsync()
        {
            await LoadPacket();
        }

        bool isLongPacket = true;

        public async Task LoadPacket()
        {
            byte[] readDgramBuf = new byte[16 * 1024];

            // todo timeout somewhere (how long wait to receive data?)
            int datalen = 0;
            for (int i = 0; i < 50 && datalen == 0; i++)
            {
                datalen = await dgramio.ReadDgramAsync(readDgramBuf, 0);
                Thread.Sleep(100);
            }

            if (datalen == 0) throw new Exception("protocol error: timeout read");

            if (QuicModelCoding.IsLongHeaderPacket(readDgramBuf))
            {
                var type = QuicModelCoding.DecodeLHPType(readDgramBuf);
                Memory<byte> srcId, destId;
                QuicModelCoding.DecodeLHPConnIds(readDgramBuf, out srcId, out destId);
                QuicConnection connection = null;

                for (int i = 0; i < connections.Count; i++)
                {
                    var current = connections[i].ServerConnectionId;
                    if (MemOps.Memcmp(destId.Span, new Span<byte>(current, 0, current.Length)))
                    {
                        connection = connections[i];
                        break;
                    }
                }

                if (connection == null)
                {
                    connection = new QuicConnection(this);
                }

                connection.BufferPacket(readDgramBuf, 0, datalen);
                await connection.AcceptClient();

            }
            else throw new NotImplementedException();

            // buffer.Append(readDgramBuf, 0, datalen);

        }

        private async Task LoadDgram()
        {
            
        }
    }
}
