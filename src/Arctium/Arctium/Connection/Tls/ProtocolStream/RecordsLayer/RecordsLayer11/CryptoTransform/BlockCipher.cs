using Arctium.Connection.Tls.Protocol.BinaryOps;
using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    class BlockCipher : Cipher
    {
        SymmetricAlgorithm readCipher;
        SymmetricAlgorithm writeCipher;
        HmacService hmacService;
        ///<summary>Initialization vector length in bytes</summary>
        private readonly int IVLength;

        public BlockCipher(SymmetricAlgorithm readAlgorithm, SymmetricAlgorithm writeAlgorithm, HmacService hmacService)
        {
            this.readCipher = readAlgorithm;
            this.writeCipher = writeAlgorithm;
            IVLength = readAlgorithm.KeySize / 8;
            this.hmacService = hmacService;
        }

        private byte[] GetIV(byte[] buffer, int offset)
        {
            byte[] iv = new byte[IVLength];
            for (int i = 0; i < IVLength; i++)
            {
                iv[i] = buffer[i + offset];
            }

            return iv;
        }

        public override byte[] EncryptToCiphertextFragment(byte[] buffer, int offset, int length)
        {
            throw new NotImplementedException();
        }

        public override byte[] DecryptToCompressedFragment(byte[] buffer, int offset, int length)
        {
            byte[] iv = GetIV(buffer, offset);
            readCipher.Padding = PaddingMode.None;
            readCipher.IV = iv;

            var decryptor = readCipher.CreateDecryptor();

            byte[] plaintext = new byte[length - IVLength];

            int ciphertextLength = length - IVLength;
            int decryptedBytesCount = decryptor.TransformBlock(buffer, offset + IVLength, ciphertextLength, plaintext, 0);

            
            
            return plaintext;
        }
    }
}
