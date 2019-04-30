namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.CryptoTransform
{
    abstract class CipherTransform
    {
        ///<param name="buffer">Buffer contains compressed bytes</param>
        ///<returns>Tls plaintext fragment</returns>
        public abstract byte[] Decrypt(byte[] buffer, int offset, int length, ulong seqNumber);

        ///<returns>TlsCiphertext fragment</returns>
        ///<param name="buffer">Buffer contains TlsCompressed framgnet</param>
        public abstract byte[] Encrypt(byte[] buffer, int offset, int length, ulong seqNumber);
    }
}
