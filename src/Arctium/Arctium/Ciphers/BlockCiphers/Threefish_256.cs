using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public class Threefish_256 : Threefish
    {
        public Threefish_256(byte[] key) : base(key)
        {
            Validation.Length(key, 32, nameof(key));
        }

        public override void Encrypt(byte[] input, long inputOffset, byte[] output, long outputOffset, byte[] tweak)
        {
            Validation.Length(tweak, 16, nameof(tweak));

            ulong t0 = MemMap.ToULong8BytesLE(tweak, 0);   
            ulong t1 = MemMap.ToULong8BytesLE(tweak, 8);   

            ThreefishAlgorithm.Encrypt256(input, inputOffset, output, outputOffset, t0, t1, context);
        }

        public override void Decrypt(byte[] input, long inputOffset, byte[] output, long outputOffset, byte[] tweak)
        {
            Validation.Length(tweak, 16, nameof(tweak));

            ulong t0 = MemMap.ToULong8BytesLE(tweak, 0);   
            ulong t1 = MemMap.ToULong8BytesLE(tweak, 8);   

            ThreefishAlgorithm.Decrypt256(input, inputOffset, output, outputOffset, t0, t1, context);
        }
    }
}
