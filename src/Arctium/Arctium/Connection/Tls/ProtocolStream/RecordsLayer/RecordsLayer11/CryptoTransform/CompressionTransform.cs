namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    abstract class CompressionTransform
    {

        ///<returns>TlsCompressed fragment</returns>
        ///<param name="buffer">Buffer that contains TlsPlaintext fragment</param>
        public abstract byte[] Compress(byte[] buffer, int offset, int length);

        ///<summary>TlsPlaintext fragment</summary>
        public abstract byte[] Decompress(byte[] buffer, int offset, int length);
    }
}
