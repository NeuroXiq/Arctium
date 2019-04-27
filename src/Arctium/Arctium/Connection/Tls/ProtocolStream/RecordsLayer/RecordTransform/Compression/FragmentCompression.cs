namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordTransform.Compression
{
    public abstract class FragmentCompression
    {

        public abstract int Compress(byte[] sourceBuffer, int sourceOffset, int length, byte[] buffer, int bufferOffset);
        public abstract int Decompress(byte[] sourceBuffer, int sourceOffset, int length, byte[] buffer, int bufferOffset);
        public abstract int CompressLength(byte[] sourceBuffer, int sourceOffset, int length);
        public abstract int DecompressLength(byte[] sourceBuffer, int sourceOffset, int length);
        
    }
}
