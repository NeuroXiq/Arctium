using Arctium.Connection.Tls.Tls13.Model;
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
        private Validate validate;

        public Tls13Protocol(Stream stream)
        {
            this.validate = new Validate();
            this.streamBuffer = new BufferForStream(stream);
            this.recordLayer = new RecordLayer(streamBuffer, validate);
            this.handshakeReader = new HandshakeReader(recordLayer, validate);
        }

        public void OpenServer()
        {
            ClientHello hello = handshakeReader.ReadClientHello();


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
