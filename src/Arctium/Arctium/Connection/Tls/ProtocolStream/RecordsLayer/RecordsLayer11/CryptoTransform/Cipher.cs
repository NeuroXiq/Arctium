using Arctium.Connection.Tls.CryptoConfiguration;
using System.Security.Cryptography;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.RecordsLayer11.CryptoTransform
{
    class Cipher
    {
        SymmetricAlgorithm readCipher;
        SymmetricAlgorithm writeCipher;
        public CipherType CipherType { get; private set; }
        public int KeySize { get; private set;}

        public Cipher(CipherType type, SymmetricAlgorithm readAlgorithm, SymmetricAlgorithm writeAlgorithm)
        {
            readCipher = readAlgorithm;
            writeCipher = writeAlgorithm;
            CipherType = type;
            KeySize = readAlgorithm.KeySize;
        }

        public byte[] EncryptFragment(byte[] buffer, int offset, int length, byte[] outputBuffer, int outputOffset)
        {
            return null;
        }

        public byte[] DecryptFragment(byte[] buffer, int offset, int length, byte[] outputBuffer, int outputOffset)
        {
            var decryptor = readCipher.CreateDecryptor();
            
            byte[] plaintext = new byte[length - IVLength];
            
            int ciphertextLength = length - IVLength;
            int decryptedBytesCount = decryptor.TransformBlock(buffer, offset + IVLength, ciphertextLength, plaintext, 0);
        }
    }
}
