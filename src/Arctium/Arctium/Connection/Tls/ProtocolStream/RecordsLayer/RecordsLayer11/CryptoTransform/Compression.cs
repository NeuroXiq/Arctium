namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    abstract class Compression
    {

        ///<returns>TlsCompressed fragment</returns>
        ///<param name="buffer">Buffer that contains TlsPlaintext fragment</param>
        public abstract int Compress(byte[] buffer, int offset, int length, byte[] outputBuffer, int outputBufferOffset);

        ///<summary>TlsPlaintext fragment</summary>
        public abstract int Decompress(byte[] buffer, int offset, int length, byte[] outputBuffer, int outputBufferOffset);

        public abstract int GetCompressedLength(byte[] buffer, int offset, int length);

        public abstract int GetDecompressedLength(byte[] buffer, int offset, int length);

    }
}
