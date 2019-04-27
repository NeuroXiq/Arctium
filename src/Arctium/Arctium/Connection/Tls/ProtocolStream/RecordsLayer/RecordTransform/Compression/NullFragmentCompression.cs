using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordTransform.Compression
{
    class NullFragmentCompression : FragmentCompression
    {
        public override int Compress(byte[] sourceBuffer, int sourceOffset, int length, byte[] buffer, int bufferOffset)
        {
            Array.Copy(sourceBuffer, sourceOffset, buffer, sourceOffset, length);

            return length;
        }

        public override int CompressLength(byte[] sourceBuffer, int sourceOffset, int length)
        {
            return length;
        }

        public override int Decompress(byte[] sourceBuffer, int sourceOffset, int length, byte[] buffer, int bufferOffset)
        {
            Array.Copy(sourceBuffer, sourceOffset, buffer, sourceOffset, length);

            return length;
        }

        public override int DecompressLength(byte[] sourceBuffer, int sourceOffset, int length)
        {
            return length;
        }
    }
}
