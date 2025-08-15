using Arctium.Cryptography.HashFunctions.Hashes;
using Arctium.Shared;

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

        /// <summary>
        /// HMAC result length in bytes
        /// It is also equal to hash size of the underlying hash fuction (HasSizeBytes of the HashFunction class)
        /// </summary>
        public int HashFunctionHashSizeBytes { get { return hashFunction.HashSizeBytes; } }

        private HashFunction hashFunction;
        private byte[] buf1;
        private byte[] buf2;
        private byte[] key;

        public HMAC(HashFunction hashFunction, byte[] key, int keyOffset, int keyLength)
        {
            this.hashFunction = hashFunction;
            buf1 = new byte[hashFunction.InputBlockSizeBytes];
            buf2 = new byte[hashFunction.InputBlockSizeBytes];
            ChangeKey(key, keyOffset, keyLength);
        }

        public void ChangeKey(byte[] key) => ChangeKey(key, 0, key.Length);

        public void ChangeKey(byte[] key, long offset, long length)
        {
            hashFunction.Reset();
            int b = hashFunction.InputBlockSizeBytes;
            MemOps.MemsetZero(buf1, 0, buf1.Length);

            if (length > b)
            {
                hashFunction.HashBytes(key, 0, key.Length);
                byte[] keyHashTemp = hashFunction.HashFinal();
                hashFunction.Reset();

                MemCpy.Copy(keyHashTemp, 0, buf1, 0, keyHashTemp.Length);
            }
            else
            {
                MemCpy.Copy(key, offset, buf1, 0, length);
            }

            MemCpy.Copy(buf1, buf2);

            for (int i = 0; i < b; i++) buf1[i] ^= IPadByte;
            for (int i = 0; i < b; i++) buf2[i] ^= OPadByte;

            hashFunction.HashBytes(buf1);
        }

        public void Reset()
        {
            hashFunction.Reset();
            hashFunction.HashBytes(buf1);
        }

        public void ProcessBytes(byte[] text) => ProcessBytes(text, 0, text.Length);

        public void ProcessBytes(byte[] text, long textOffset, long textLength)
        {
            hashFunction.HashBytes(text, textOffset, textLength);
        }

        // public void ComputeHMAC(byte[] text, byte[] output) => ComputeHMAC(text, 0, text.Length, output, 0);

        public void Final( byte[] output, long outputOffset)
        {
            byte[] hash1, hash2;

            // hashFunction.Reset();
            
            hash1 = hashFunction.HashFinal();

            hashFunction.Reset();

            hashFunction.HashBytes(buf2);
            hashFunction.HashBytes(hash1);
            hash2 = hashFunction.HashFinal();

            MemCpy.Copy(hash2, 0, output, outputOffset, hash2.Length);

            Reset();
        }
    }
}
