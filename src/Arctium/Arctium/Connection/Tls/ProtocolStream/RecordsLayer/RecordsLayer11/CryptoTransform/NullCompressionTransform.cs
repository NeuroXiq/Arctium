using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    class NullCompressionTransform : CompressionTransform
    {
        public override byte[] Compress(byte[] buffer, int offset, int length)
        {
            if (buffer.Length == length && offset == 0) return buffer;

            byte[] identity = new byte[length];
            Array.Copy(buffer, offset, identity, 0, length);

            return identity;
        }

        public override byte[] Decompress(byte[] buffer, int offset, int length)
        {
            if (buffer.Length == length && offset == 0) return buffer;

            byte[] identity = new byte[length];
            Array.Copy(buffer, offset, identity, 0, length);

            return identity;
        }
    }
}
