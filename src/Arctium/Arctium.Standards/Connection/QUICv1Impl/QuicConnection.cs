using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.Connection.QUICv1Impl.Model;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl
{
    internal class QuicConnection
    {
        private QuicServerProtocol quicServer;
        private ByteBuffer packets = new ByteBuffer();
        private QuicCrypto crypto = new QuicCrypto();

        public byte[] ServerConnectionId { get; set; }
        public byte[] ClientConnectionId { get; set; }

        public QuicConnection(QuicServerProtocol quicServer)
        {
            this.quicServer = quicServer;
        }

        internal void BufferPacket(byte[] buff, int offs, int len)
        {
            packets.Append(buff, offs, len);
        }

        public async Task AcceptClient()
        {
            if (packets.DataLength == 0) await quicServer.LoadPacket();

            
            LongHeaderPacket.DecodeVerDestIDSrcID(packets.Buffer, 0, out var ver, out var destId, out var _);
            crypto.SetupInitCrypto(destId.ToArray());
            crypto.HeaderProtectionDecrypt(packets.Buffer, 0);

            var r = QuicModelCoding.DecodeInitialPacket(packets.Buffer, 0);
            
            Debugger.Break();
        }

        public void ReadDataAsync()
        {
        
        }

        public void WriteDataAsync()
        {
            
        }
    }
}
