using Arctium.Cryptography.Ciphers.BlockCiphers;
using Arctium.Cryptography.HashFunctions.MAC;
using Arctium.Shared.Helpers;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using System;

namespace Arctium.Cryptography.Ciphers.StreamCiphers
{
    /// <summary>
    /// RFC 7539
    /// </summary>
    public class AEAD_CHACHA20_POLY1305 : AEAD
    {
        const int AuthTagLen = 16;
        Poly1305 poly1305;
        ChaCha20 chacha20;
        byte[] poly1305Key;
        byte[] zero32bytes;
        byte[] nonce;
        byte[] macDataTemp;

        public AEAD_CHACHA20_POLY1305(byte[] chacha20Key) : base(AuthTagLen)
        {
            chacha20 = new ChaCha20(chacha20Key, new byte[12]);
            poly1305 = new Poly1305(new byte[32]);
            poly1305Key = new byte[32];
            zero32bytes = new byte[32];
            nonce = new byte[12];
            macDataTemp = new byte[15 + 4 + 4]; // 15 - max padding (zero bytes), 4 - aad.length, 4 - ciphertext.length)
        }

        public override void AuthenticatedDecryption(byte[] iv,
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
            out bool authenticationTagValidationResult)
        {
            Validation.Length(ivLength, 12, nameof(ivLength));
            Validation.LengthMax(ciphertextLength, uint.MaxValue, nameof(ciphertextLength));
            Validation.LengthMax(aLength, uint.MaxValue, nameof(aLength));

            authenticationTagValidationResult = false;
        }

        private void Prepare(byte[] iv, long ivOffset, long ivLength)
        {
            MemCpy.Copy(iv, ivOffset, nonce, 0, ivLength);
            chacha20.Reset(nonce, 0);

            chacha20.Encrypt(zero32bytes, 0, poly1305Key, 0, 32);
            
            poly1305.Reset(poly1305Key);
            chacha20.Reset();
        }

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
            Validation.Length(ivLength, 12, nameof(ivLength));
            Validation.LengthMax(pLength, uint.MaxValue, nameof(pLength));
            Validation.LengthMax(aLength, uint.MaxValue, nameof(aLength));

            Prepare(iv, ivOffset, ivLength);

            chacha20.Encrypt(p, pOffset, ciphertextOutput, ciphertextOutputOffset, pLength);
            ComputeMAC(a, aOffset, aLength,
                ciphertextOutput, ciphertextOutputOffset, pLength,
                authenticationTagOutput, authenticationTagOutputOffset);
        }

        void ComputeMAC(byte[] a, long aOffset, long aLen,
            byte[] ciphertext, long ciphertextOffs, long ciphertextLen,
            byte[] tagOutput, long tagOutputOffset)
        {
            MemOps.MemsetZero(macDataTemp);

            long padLen = 16 - (aLen % 16);
            padLen = padLen == 16 ? 0 : padLen;

            // tag + padding
            poly1305.Process(a, aOffset, aLen);
            poly1305.Process(macDataTemp, 0, padLen);

            // ciphertext + padding
            poly1305.Process(ciphertext, ciphertextOffs, ciphertextLen);
            padLen = 16 - (ciphertextLen % 16);
            padLen = padLen == 16 ? 0 : padLen;
            poly1305.Process(macDataTemp, 0, padLen);

            // additionaldata len + ciphertext len
            MemMap.ToBytes1UIntLE((uint)aLen, macDataTemp, 0);
            MemMap.ToBytes1UIntLE((uint)ciphertextLen, macDataTemp, 4);
            poly1305.Process(macDataTemp, 0, 8);

            byte[] tag = poly1305.Final();
            MemCpy.Copy(tag, 0, tagOutput, tagOutputOffset, tag.Length);
        }
    }
}
