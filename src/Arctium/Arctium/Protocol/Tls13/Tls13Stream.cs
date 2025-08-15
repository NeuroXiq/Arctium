using System;
using System.IO;
using Arctium.Shared;
using Arctium.Protocol.Tls13Impl.Protocol;

namespace Arctium.Protocol.Tls13
{
    public abstract class Tls13Stream : Stream
    {
        /// <summary>
        /// if true stream was opened successfully and can read/write data otherwise tls cannot be used to exchanged data
        /// </summary>
        public abstract bool IsConnected { get; }

        public abstract void PostHandshakeKeyUpdate(bool updateRequested);

        public abstract void WaitForAnyProtocolData();

        /// <summary>
        /// If protocol state is connected then close notify is sent to other party and state is moved to closed
        /// If protocol statei is closed then do nothing.
        /// If protocol has other state throws exception (command is valid only for 'close' and 'connected' states)
        /// </summary>
        public abstract void Close();
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

        public override bool IsConnected => protocol.state == ClientProtocolState.Connected;

        public override void Close()
        {
            protocol.Close();
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override void PostHandshakeKeyUpdate(bool updateRequested)
        {
            protocol.PostHandshakeKeyUpdate(updateRequested);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Validation.NotNegative(count, nameof(count));

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

        public override void WaitForAnyProtocolData()
        {
            protocol.WaitForAnyProtocolData();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Validation.NotNegative(count, nameof(count));

            protocol.WriteApplicationData(buffer, offset, count);
        }
    }

    public abstract class Tls13ServerStream : Tls13Stream
    {
        /// <summary>
        /// Post handshake client authentication. Can throw exception if state is invalid
        /// </summary>
        /// <exception cref="">Throws exception if not configured or if client do not support post handshake authentication</exception>
        public abstract void PostHandshakeClientAuthentication();
    }

    class Tls13ServerStreamInternal : Tls13ServerStream
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

        public override bool IsConnected => protocol.State == ServerProtocolState.Connected;

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override void PostHandshakeClientAuthentication()
        {
            protocol.PostHandshakeClientAuthentication();
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

        public override void PostHandshakeKeyUpdate(bool updateRequested)
        {
            protocol.PostHandshakeKeyUpdate(true);
        }

        public override void WaitForAnyProtocolData() => protocol.WaitForAnyProtocolData();

        public override void Close() => protocol.Close();
    }
}
