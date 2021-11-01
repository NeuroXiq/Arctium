using Arctium.Cryptography.Ciphers.BlockCiphers.Algorithms;

namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public abstract class AES : BlockCipher
    {
        public AESAlgorithm.Context context;

        public AES(byte[] key, int inputBlockLengthBits, BlockCipherMode mode) : base(key, inputBlockLengthBits, mode)
        {
            context = AESAlgorithm.Initialize(key); 
        } 

    }
}
