namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.CryptoTransform
{
    class TlsRecordTransform
    {
        CipherTransform cipherTransform;
        CompressionTransform compressionTransform;

        public TlsRecordTransform(CipherTransform cipherTransform, CompressionTransform compressionTransform)
        {
            this.cipherTransform = cipherTransform;
            this.compressionTransform = compressionTransform;
        }


        ///<summary></summary>
        ///<returns>TlsPlaintext fragment</returns>
        public byte[] ForwardTransform(byte[] buffer, int offset, int length, ulong seqNum)
        {
            byte[] compressed = compressionTransform.Compress(buffer, offset, length);
            byte[] encrypted = cipherTransform.Encrypt(buffer, offset, length, seqNum);

            return encrypted;
        }

        ///<returns>TlsPlaintext fragment</returns>
        public byte[] ReverseTransform(byte[] buffer, int offset, int length, ulong seqNum)
        {
            byte[] decrypted = cipherTransform.Decrypt(buffer, offset, length, seqNum);
            byte[] decompressed = compressionTransform.Decompress(buffer, offset, length);

            return decompressed;
        }
    }
}
