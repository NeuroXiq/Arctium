using Arctium.Connection.Tls.Tls13.Protocol;
using System;
using System.IO;

namespace Arctium.Connection.Tls.Tls13.API
{
    public abstract class Tls13Stream : Stream
    {
        
    }

    class Tls13StreamInternal : Tls13Stream
    {
        private Tls13Protocol protocol;

        public Tls13StreamInternal(Tls13Protocol protocol)
        {
            this.protocol = protocol;
        }

        public override bool CanRead => throw new NotImplementedException();

        public override bool CanSeek => throw new NotImplementedException();

        public override bool CanWrite => throw new NotImplementedException();

        public override long Length => throw new NotImplementedException();

        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return protocol.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            protocol.Write(buffer, offset, count);
        }
    }
}
