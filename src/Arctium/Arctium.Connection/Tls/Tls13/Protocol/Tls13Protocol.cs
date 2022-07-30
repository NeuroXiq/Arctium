using Arctium.Shared.Helpers.Buffers;
using System;
using System.IO;

namespace Arctium.Connection.Tls.Tls13.Protocol
{
    class Tls13Protocol
    {
        private HandshakeReader handshakeReader;
        private BufferForStream streamBuffer;
        private RecordLayer recordLayer;

        public Tls13Protocol(Stream stream)
        {
            this.streamBuffer = new BufferForStream(stream);
            this.recordLayer = new RecordLayer(streamBuffer);

            this.handshakeReader = new HandshakeReader(recordLayer);
        }

        public void OpenServer()
        {
            handshakeReader.ReadClientHello();
        }

        internal void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        internal int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }
}
