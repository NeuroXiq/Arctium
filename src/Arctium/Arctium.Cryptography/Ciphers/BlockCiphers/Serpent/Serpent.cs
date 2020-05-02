using Arctium.Cryptography.Ciphers.BlockCiphers.Shared;
using Arctium.Cryptography.Ciphers.Helpers;
using Arctium.Shared.Helpers.Buffers;
using System;

namespace Arctium.Cryptography.Ciphers.BlockCiphers.Serpent
{
    /// <summary>
    /// Block cipher created by Ross Anderson, Eli Biham and Lars Knudsen.
    /// One of the AES finalist. 256 bits key, 32-rounds.
    /// </summary>
    public class Serpent : BlockCipher
    {
        /// <summary>
        /// Input block length in bits
        /// </summary>
        const int CipherInputBlockLength = 128;

        int[] validKeyLengths = new int[] { 256 };

        public Serpent(byte[] key, byte[] initializationVector, BlockCipherMode mode) : base(key, initializationVector, CipherInputBlockLength, mode)
        {
            if (key == null) throw new ArgumentNullException("key");
            CiphersValidation.ThrowIfInvalidKeyLength("Serpent", validKeyLengths, key.Length);
        }

        public Serpent(byte[] key, BlockCipherMode mode) : base(key, null, CipherInputBlockLength, mode)
        {

        }

        /// <summary>
        /// If key length is less than 256 bits, 
        /// key can be expanded by appending bit of value 1 
        /// and rest bits of value 0 to match expected size of 256 bits
        /// </summary>
        /// <param name="currentKey">Key to be expanded</param>
        /// <returns>
        /// Expanded key, if key match 256-bits returns <paramref name="currentKey"/> otherwise
        /// creates new byte array with expanded key
        /// </returns>
        public static byte[] ExpandKey(byte[] currentKey)
        {
            if (currentKey == null) throw new ArgumentNullException(nameof(currentKey));
            if (currentKey.Length > 32) throw new ArgumentException("currentKey parameter exceed 256 bits in length");
            if (currentKey.Length == 32) return currentKey;

            byte[] expandedKey = new byte[32];
            MemCpy.Copy(currentKey, 0, expandedKey, 0, currentKey.Length);
            expandedKey[currentKey.Length] = 0x80;

            return expandedKey;
        }

        public override long Decrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            throw new System.NotImplementedException();
        }

        public override long Encrypt(byte[] input, long offset, byte[] output, long outputOffset, long length)
        {
            throw new System.NotImplementedException();
        }
    }
}
