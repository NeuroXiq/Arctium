using Arctium.Connection.Tls.Operator;
using System;
using System.IO;

namespace Arctium.Connection.Tls
{
    public class TlsStream : Stream
    {
        TlsProtocolOperator tlsOperator;

        internal TlsStream(TlsProtocolOperator tlsOperator)
        {
            this.tlsOperator = tlsOperator;
        }

        #region Base Stream abstract

        public override bool CanRead
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public override bool CanSeek
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public override bool CanWrite
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public override long Length
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public override long Position
        {
            get
            {
                throw new NotImplementedException();
            }

            set
            {
                throw new NotImplementedException();
            }
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return tlsOperator.ReadApplicationData(buffer, offset, count);
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
            tlsOperator.WriteApplicationData(buffer, offset, count);
        }

        ///<summary>Sends close notify</summary>
        public override void Close()
        {
            tlsOperator.CloseNotify();
        }

        #endregion Base Stream abstract

    }
}
