using System;
using System.Collections.Generic;
using System.Text;
using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;
using Arctium.Shared.Helpers.Buffers;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public class Threefish_256 : Threefish
    {
        public Threefish_256(byte[] key) : base(key) { }

        public override void Encrypt(byte[] input, long inputOffset, byte[] output, long outputOffset, byte[] tweak)
        {
            ulong t0 = MemMap.ToULong8BytesLE(tweak, 0);   
            ulong t1 = MemMap.ToULong8BytesLE(tweak, 8);   

            ThreefishAlgorithm.Encrypt256(input, inputOffset, output, outputOffset, t0, t1, context);
        }

        public override void Decrypt(byte[] input, long inputOffset, byte[] output, long outputOffset, byte[] tweak)
        {
            ulong t0 = MemMap.ToULong8BytesLE(tweak, 0);   
            ulong t1 = MemMap.ToULong8BytesLE(tweak, 8);   

            ThreefishAlgorithm.Decrypt256(input, inputOffset, output, outputOffset, t0, t1, context);
        }
    }
}
