namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    public abstract class BlockCipher
    {
        public int InputBlockLength { get; private set;}

        private byte[] key;

        public BlockCipher(byte[] key, int inputBlockLength)
        {
            InputBlockLength = inputBlockLength;
            this.key = key;
        }

        public abstract long Encrypt(byte[] buffer, long offset, byte[] outputBuffer, long outputOffset, long length);

        public abstract long Decrypt(byte[] buffer, long offset, byte[] outputBuffer, long outputOffset, long length);
    }
}
