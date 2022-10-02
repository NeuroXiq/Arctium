using Arctium.Standards.Connection.Tls.Tls13.Protocol;
using Arctium.Shared.Helpers.Buffers;
using System;
using System.IO;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public abstract class Tls13Stream : Stream
    {
        
    }

    class Tls13ClientStreamInternal : Tls13Stream
    {
        Tls13ClientProtocol protocol;
        int remainingApplicationData;

        public Tls13ClientStreamInternal(Tls13ClientProtocol protocol)
        {
            this.protocol = protocol;
            remainingApplicationData = 0;
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
            if (remainingApplicationData == 0)
            {
                protocol.LoadApplicationData();
                remainingApplicationData = protocol.ApplicationDataLength;
            }

            int maxRead = count < remainingApplicationData ? count : remainingApplicationData;

            MemCpy.Copy(protocol.ApplicationDataBuffer, protocol.ApplicationDataLength - remainingApplicationData, buffer, offset, maxRead);
            remainingApplicationData -= maxRead;

            return maxRead;
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
            protocol.WriteApplicationData(buffer, offset, count);
        }
    }

    class Tls13ServerStreamInternal : Tls13Stream
    {
        private Tls13ServerProtocol protocol;
        private int applicationDataCursor;

        public Tls13ServerStreamInternal(Tls13ServerProtocol protocol)
        {
            this.protocol = protocol;
            applicationDataCursor = 0;
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
            if (protocol.ApplicationDataLength == 0 || applicationDataCursor == protocol.ApplicationDataLength)
            {
                applicationDataCursor = 0;
                protocol.LoadNextApplicationData();
            }

            int maxRead = protocol.ApplicationDataLength - applicationDataCursor;
            
            maxRead = maxRead < count ? maxRead : count;

            MemCpy.Copy(protocol.ApplicationDataBuffer, applicationDataCursor, buffer, offset, maxRead);

            applicationDataCursor += maxRead;

            return maxRead;
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
            protocol.WriteApplicationData(buffer, offset, count);
        }
    }
}
