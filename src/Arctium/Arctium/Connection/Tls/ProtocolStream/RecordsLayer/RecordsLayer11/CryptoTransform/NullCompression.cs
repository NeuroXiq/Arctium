using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    class NullCompression : Compression
    {
        public override int Compress(byte[] buffer, int offset, int length, byte[] outputBuffer, int outputBufferOffset)
        {
            byte[] identity = new byte[length];
            Array.Copy(buffer, offset, outputBuffer, outputBufferOffset, length);

            return length;
        }

        public override int Decompress(byte[] buffer, int offset, int length, byte[] outputBuffer, int outputBufferOffset)
        {
            byte[] identity = new byte[length];
            Array.Copy(buffer, offset, identity, 0, length);

            return length;
        }

        public override int GetCompressedLength(byte[] buffer, int offset, int length)
        {
            return length;
        }

        public override int GetDecompressedLength(byte[] buffer, int offset, int length)
        {
            return length;
        }
    }
}
