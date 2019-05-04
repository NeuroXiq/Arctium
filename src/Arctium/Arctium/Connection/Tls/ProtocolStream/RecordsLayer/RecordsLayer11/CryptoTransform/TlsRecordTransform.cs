using Arctium.Connection.Tls.Buffers;
using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    class TlsRecordTransform
    {
        Cipher cipherTransform;
        CompressionTransform compressionTransform;
        HmacService hmacService;

        public TlsRecordTransform(Cipher cipherTransform, CompressionTransform compressionTransform, HmacService hmacService)
        {
            this.cipherTransform = cipherTransform;
            this.compressionTransform = compressionTransform;
            this.hmacService = hmacService;
        }


        ///<summary></summary>
        ///<returns>TlsPlaintext fragment</returns>
        public byte[] ForwardTransform(byte[] buffer, int offset, int length, ulong seqNum)
        {
            // 0. compress
            // 1. mac 
            // 2. build encrypted record fragment
            //

            byte[] compressed = compressionTransform.Compress(buffer, offset, length);

            if (buffer.Length == length && offset == 0) return buffer;

            byte[] asdf = new byte[length];
            Array.Copy(buffer, offset, asdf, 0, length);

            return asdf;
            //return encrypted;
        }

        ///<returns>TlsPlaintext fragment</returns>
        public byte[] ReverseTransform(byte[] buffer, int offset, int length, ulong seqNum)
        {
            byte[] hmac;
            byte[] decrypted = cipherTransform.DecryptToCompressedFragment(buffer, offset, length, out hmac);
            byte[] decompressed = compressionTransform.Decompress(buffer, offset, length);

            hmacService.ComputeReadHmac(decompressed, 0, decompressed.Length, seqNum);

            return decompressed;
        }
    }
}
