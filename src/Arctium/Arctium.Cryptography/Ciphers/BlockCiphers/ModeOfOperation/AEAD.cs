using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using System;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    /// <summary>
    /// Authenticated encryption with associated data mode of operation for block cipher
    /// </summary>
    public abstract class AEAD
    {
        private BlockCipher cipher;
        private static readonly byte[] Zero128Bytes = new byte[128];

        public AEAD(BlockCipher cipher)
        {
            if (cipher.InputBlockLengthBits != 128) throw new NotSupportedException("only 128 input block ");

            this.cipher = cipher;
        }

        /// <summary>
        /// Performs authentication encryption operation
        /// </summary>
        /// <param name="iv">Initialization vector</param>
        /// <param name="ivOffset"></param>
        /// <param name="ivLength"></param>
        /// <param name="p">Plaintext (to encrypt)</param>
        /// <param name="pOffset"></param>
        /// <param name="pLength"></param>
        /// <param name="a">Additional authenticated data</param>
        /// <param name="aOffset"></param>
        /// <param name="aLength"></param>
        /// <param name="ciphertextOutput">Output buffer to write encrypted plaintext</param>
        /// <param name="ciphertextOutputOffset"></param>
        /// <param name="authenticationTagOutput">Output buffer to write authentication tag</param>
        /// <param name="authenticationTagOutputOffset"></param>
        public abstract void AuthenticatedEncryption(byte[] iv,
            long ivOffset,
            long ivLength,
            byte[] p,
            long pOffset,
            long pLength,
            byte[] a,
            long aOffset,
            long aLength,
            byte[] ciphertextOutput,
            long ciphertextOutputOffset,
            byte[] authenticationTagOutput,
            long authenticationTagOutputOffset);

        public abstract void AuthenticatedDecryption(byte[] iv,
            long ivOffset,
            long ivLength,
            byte[] ciphertext,
            long ciphertextOffset,
            long ciphertextLength,
            byte[] a,
            long aOffset,
            long aLength,
            byte[] decryptedOutput,
            long decryptedOutputOffset,
            byte[] authenticationTag,
            long authenticationTagOffset,
            out bool authenticationTagValidationResult);
    }
}
