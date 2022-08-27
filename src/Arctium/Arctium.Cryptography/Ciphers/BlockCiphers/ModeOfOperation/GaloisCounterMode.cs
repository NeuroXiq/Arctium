using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using System;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    /// <summary>
    /// Authenticated encryption with associated data mode of operation for block cipher
    /// </summary>
    public class GaloisCounterMode : AEAD
    {
        GaloisCounterModeAlgorithm.Context context;
        private int authTagLen;
        private BlockCipher cipher;
        private static readonly byte[] Zero16Bytes = new byte[16];

        public GaloisCounterMode(BlockCipher cipher, int authTagLen) : base(cipher)
        {
            if (cipher.InputBlockLengthBits != 128) throw new NotSupportedException("only 128 input block ");

            this.cipher = cipher;
            context = GaloisCounterModeAlgorithm.Initialize(cipher);
            this.authTagLen = authTagLen;
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
                authTagLen);
        }

        public override void AuthenticatedDecryption()
        {
        }

        //byte[] h = new byte[16];
        //byte[] j0;

        //if (ivLength * 8 == 96)
        //{
        //    j0 = new byte[16];
        //}
        //else
        //{
        //    long s = (128 * SMath.DivideAndCeilUp(ivLength * 8, 128)) - (ivLength * 8);
        //    // convert to bytes
        //    long len = (ivLength * 8) + (s + 64) + (64);
        //    len = len / 8;

        //    len = (ivLength + 15) / 16;

        //    j0 = new byte[len];
        //    MemCpy.Copy(iv, ivOffset, j0, 0, ivLength);
        //    MemMap.ToBytes1ULongBE((ulong)ivLength * 8, j0, j0.Length - 8);
        //}

        //cipher.Encrypt(Zero16Bytes, 0, h, 0, 16);
    }
}
