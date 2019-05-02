using System;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.CryptoTransform
{
    class BlockCipherTransform : CipherTransform
    {
        SymmetricAlgorithm readCipher;
        SymmetricAlgorithm writeCipher;
        HMAC readMac;
        HMAC writeMac;


        public BlockCipherTransform(SymmetricAlgorithm readAlgorithm, SymmetricAlgorithm writeAlgorithm, HMAC readMac, HMAC writeMac)
        {
            this.readCipher = readAlgorithm;
            this.writeCipher = writeAlgorithm;
            this.readMac = readMac;
            this.writeMac = writeMac;
        }

        public override byte[] Decrypt(byte[] buffer, int offset, int length, ulong seqNum)
        {
            byte[] iv = new byte[16];
            for (int i = 0; i < 16; i++)
                iv[i] = buffer[offset + i];

            readCipher.IV = iv;
            readCipher.Padding = PaddingMode.None;
            readCipher.Mode = CipherMode.CBC;
            
            
            var decryptor = readCipher.CreateDecryptor(readCipher.Key, iv);
            
            byte[] decryptResult = new byte[length - 16];
            int len = length - 16;
            int iq = decryptor.TransformBlock(buffer, offset + 16, length - 16, decryptResult, 0);
            
            return null;
        }

        public override byte[] Encrypt(byte[] buffer, int offset, int length, ulong seqNum)
        {
            throw new NotImplementedException();
        }
    }
}
