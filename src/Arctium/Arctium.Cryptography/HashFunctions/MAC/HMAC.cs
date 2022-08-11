using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Cryptography.HashFunctions.MAC
{
    /// <summary>
    /// RFC 2104
    ///  HMAC: Keyed-Hashing for Message Authentication
    /// </summary>
    public class HMAC
    {
        const byte IPadByte = 0x36;
        const byte OPadByte = 0x5C;

        private HashFunction hashFunction;
        private byte[] buf1;
        private byte[] buf2;

        public HMAC(HashFunction hashFunction)
        {
            this.hashFunction = hashFunction;
            buf1 = new byte[hashFunction.InputBlockSizeBytes];
            buf2 = new byte[hashFunction.InputBlockSizeBytes];
        }

        public void ComputeHMAC(byte[] key, byte[] text, byte[] output) => ComputeHMAC(key, 0, key.Length, text, 0, text.Length, output, 0);

        public void ComputeHMAC(byte[] key,
            int keyOffset,
            int keyLength,
            byte[] text,
            int textOffset,
            int textLength,
            byte[] output,
            int outputOffset)
        {
            int b = hashFunction.InputBlockSizeBytes;
            byte[] hash1, hash2;

            MemOps.MemsetZero(buf1, 0, buf1.Length);
            hashFunction.Reset();

            if (keyLength > b)
            {
                hashFunction.HashBytes(key, 0, key.Length);
                byte[] keyHashTemp = hashFunction.HashFinal();
                hashFunction.Reset();

                MemCpy.Copy(keyHashTemp, 0, buf1, 0, keyHashTemp.Length);
            }
            else
            {
                MemCpy.Copy(key, keyOffset, buf1, 0, keyLength);
            }

            MemCpy.Copy(buf1, buf2);

            for (int i = 0; i < b; i++) buf1[i] ^= IPadByte;

            hashFunction.HashBytes(buf1);
            hashFunction.HashBytes(text, textOffset, textLength);
            hash1 = hashFunction.HashFinal();

            hashFunction.Reset();

            for (int i = 0; i < b; i++) buf2[i] ^= OPadByte;

            hashFunction.HashBytes(buf2);
            hashFunction.HashBytes(hash1);
            hash2 = hashFunction.HashFinal();

            MemCpy.Copy(hash2, 0, output, outputOffset, hash2.Length);
        }
    }
}
