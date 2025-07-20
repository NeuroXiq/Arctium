using System;
using System.Collections.Generic;
using System.Text;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;
using Arctium.Shared.Other;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public class Threefish_1024 : Threefish
    {
        public Threefish_1024(byte[] key) : base(key)
        {
            Validation.Length(key, 128, nameof(key));
        }

        public override void Encrypt(byte[] input, long inputOffset, byte[] output, long outputOffset, byte[] tweak)
        {
            Validation.Length(tweak, 16, nameof(tweak));
            
            ulong t0, t1;
            t0 = MemMap.ToULong8BytesLE(tweak, 0);
            t1 = MemMap.ToULong8BytesLE(tweak, 8);

            ThreefishAlgorithm.Encrypt1024(input, inputOffset, output, outputOffset, t0, t1, context);
        }

        public override void Decrypt(byte[] input, long inputOffset, byte[] output, long outputOffset, byte[] tweak)
        {
            Validation.Length(tweak, 16, nameof(tweak));

            ulong t0, t1;
            t0 = MemMap.ToULong8BytesLE(tweak, 0);
            t1 = MemMap.ToULong8BytesLE(tweak, 8);

            ThreefishAlgorithm.Decrypt1024(input, inputOffset, output, outputOffset, t0, t1, context);
        }
    }
}
