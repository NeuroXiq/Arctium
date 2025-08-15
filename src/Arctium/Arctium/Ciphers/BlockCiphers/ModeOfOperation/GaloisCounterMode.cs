using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;
using Arctium.Shared;
using System;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    /// <summary>
    /// Authenticated encryption with associated data mode of operation for block cipher
    /// </summary>
    public class GaloisCounterMode : AEAD
    {
        GaloisCounterModeAlgorithm.Context context;
        private BlockCipher cipher;
        private static readonly byte[] Zero16Bytes = new byte[16];

        public GaloisCounterMode(BlockCipher cipher, int authTagLen) : base(authTagLen)
        {
            if (cipher.InputBlockLengthBits != 128) throw new NotSupportedException("only 128 input block ");

            this.cipher = cipher;
            context = GaloisCounterModeAlgorithm.Initialize(cipher);
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
        public override void AuthenticatedEncryption(byte[] iv,
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
            long authenticationTagOutputOffset)
        {
            GaloisCounterModeAlgorithm.AE(context,
                iv, ivOffset, ivLength,
                p, pOffset, pLength,
                a, aOffset, aLength,
                ciphertextOutput, ciphertextOutputOffset,
                authenticationTagOutput, authenticationTagOutputOffset,
                AuthenticationTagLengthBytes);
        }

        public override void AuthenticatedDecryption(
            byte[] iv, long ivOffset, long ivLength,
            byte[] ciphertext, long ciphertextOffset, long ciphertextLength,
            byte[] a, long aOffset, long aLength,
            byte[] decryptedOutput, long decryptedOutputOffset,
            byte[] authenticationTag, long authenticationTagOffset,
            out bool authenticationTagValidationResult)
        {
            GaloisCounterModeAlgorithm.AD(context,
                iv, ivOffset, ivLength,
                ciphertext, ciphertextOffset, ciphertextLength,
                a, aOffset, aLength,
                decryptedOutput, decryptedOutputOffset,
                authenticationTag, authenticationTagOffset, AuthenticationTagLengthBytes, out authenticationTagValidationResult);
        }
    }
}
