using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer12
{
    class BlockFragmentCrypto : IFragmentDecryptor, IFragmentEncryptor
    {
        HMAC hmac;
        SymmetricAlgorithm cipher;

        int hmacSize;
        int blockSize;

        public BlockFragmentCrypto(HMAC hmac, SymmetricAlgorithm cipher)
        {
            this.hmac = hmac;
            this.cipher = cipher;

            hmacSize = hmac.HashSize / 8;
            blockSize = cipher.BlockSize / 8;
        }

        public int Decrypt(RecordData recordData, byte[] outBuffer, int outOffset)
        {
            throw new NotImplementedException();
        }

        public int Encrypt(RecordData recordData, byte[] outBuffer, int outOffset)
        {
            throw new NotImplementedException();
        }

        public int GetDecryptedLength(int encryptedFragmentLength)
        {
            throw new NotImplementedException();
        }

        public int GetEncryptedLength(int plaintextFragmentLength)
        {
            int paddingLength = blockSize - ((plaintextFragmentLength + 1) % blockSize);




        }

        public byte[] CreatePadding(int baseLength)
        {
            int paddingLength = blockSize - ((baseLength + 1) % blockSize);

            byte[] padding = new byte[paddingLength];
            for (int i = 0; i < paddingLength; i++)
            {
                padding[i] = (byte)(paddingLength - 1);
            }

            return padding;

        }
    }
}
