using Arctium.Connection.Tls.CryptoConfiguration;
using System;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    class TlsRecordTransform
    {
        Cipher ciphers;
        Compression compressionTransform;
        HmacService hmacService;

        //
        // Fragment structure depends on current Cipher.CipherType value.
        private struct RecordFragmentStructure
        {
            public int MacLength;
            public int MacOffset;

            public int ContentLength;
            public int ContentOffset;

            public int PaddingLength;
            public int PaddingOffset;
        }

        public TlsRecordTransform(Cipher cipherTransform, Compression compressionTransform, HmacService hmacService)
        {
            this.ciphers = cipherTransform;
            this.compressionTransform = compressionTransform;
            this.hmacService = hmacService;
        }
        
        public byte[] ForwardTransform(byte[] buffer, int offset, int length, ulong seqNum)
        {
            // 0. compress
            // 1. mac 
            // 2. build encrypted record fragment
            //

            //byte[] compressed = compressionTransform.Compress(buffer, offset, length);

            if (buffer.Length == length && offset == 0) return buffer;

            byte[] asdf = new byte[length];
            Array.Copy(buffer, offset, asdf, 0, length);

            return asdf;
            //return encrypted;
        }

        public byte[] ReverseTransform(byte[] buffer, int offset, int length, ulong seqNum)
        {
            byte[] decrypted = new byte[length];

            ciphers.DecryptFragment(buffer, offset, length, decrypted, 0);

            RecordFragmentStructure structure = GetFragmentStructure(decrypted);

            //TODO TLS11_TlsRecordTransform: ASSUME THAT COMPRESSTION == NULL
            compressionTransform.Decompress(
                decrypted,
                structure.ContentOffset,
                structure.ContentLength,
                decrypted,
                0);


            return decrypted;
        }

        private RecordFragmentStructure GetFragmentStructure(byte[] decrypted)
        {
            RecordFragmentStructure s = new RecordFragmentStructure();

            if (ciphers.CipherType == CipherType.Block)
            {
                s.PaddingLength = decrypted[decrypted.Length - 1] + 1;

                //first byte of padding
                s.PaddingOffset = decrypted.Length - s.PaddingLength;

                //first byte of MAC
                s.MacOffset = s.PaddingOffset - s.PaddingLength;
                s.MacLength = hmacService.HashSize / 8;

                //first byte of fragment.content
                s.ContentOffset = ciphers.KeySize / 8;
                s.ContentLength = decrypted.Length - s.MacLength - s.PaddingLength;
            }
            else
            {
                s.PaddingLength = 0;
                s.PaddingOffset = -1;

                s.MacLength = hmacService.HashSize / 8;
                s.MacOffset = decrypted.Length - s.MacLength;

                s.ContentOffset = 0;
                s.ContentLength = decrypted.Length - s.PaddingLength;
            }

            return s;
        }
    }
}
