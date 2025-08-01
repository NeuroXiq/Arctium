using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;
using Arctium.Shared;
using System;

namespace Arctium.Cryptography.Ciphers.BlockCiphers.ModeOfOperation
{
    public class CCMMode : AEAD
    {
        BlockCipher cipher;
        CCMModeAlgorithm.Context context;

        public CCMMode(BlockCipher cipher, int authenticationTagLength) : base(authenticationTagLength)
        {
            if (cipher.InputBlockLengthBits != 128) throw new NotSupportedException("block length for blockcipher must be 128 bits");
            this.cipher = cipher;
            context = CCMModeAlgorithm.Init(cipher);
        }

        public override void AuthenticatedDecryption(byte[] iv, long ivOffset, long ivLength, 
            byte[] ciphertext, long ciphertextOffset, long ciphertextLength,
            byte[] a, long aOffset, long aLength,
            byte[] decryptedOutput, long decryptedOutputOffset,
            byte[] authenticationTag, long authenticationTagOffset,
            out bool authenticationTagValidationResult)
        {
            CCMModeAlgorithm.DecryptionVerification(context,
                iv, ivOffset, ivLength,
                ciphertext, ciphertextOffset, ciphertextLength,
                a, aOffset, aLength,
                decryptedOutput, decryptedOutputOffset,
                authenticationTag, authenticationTagOffset, 
                AuthenticationTagLengthBytes,
                out authenticationTagValidationResult);
        }

        public override void AuthenticatedEncryption(byte[] iv, long ivOffset, long ivLength, 
            byte[] p, long pOffset, long pLength,
            byte[] a, long aOffset, long aLength, 
            byte[] ciphertextOutput, long ciphertextOutputOffset,
            byte[] authenticationTagOutput, long authenticationTagOutputOffset)
        {
            CCMModeAlgorithm.GenerationEncryption(context,
                iv, ivOffset, ivLength,
                p, pOffset, pLength,
                a, aOffset, aLength,
                ciphertextOutput, ciphertextOutputOffset,
                authenticationTagOutput, authenticationTagOutputOffset,
                AuthenticationTagLengthBytes);
        }
    }
}
