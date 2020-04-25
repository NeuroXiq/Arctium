namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    /// <summary>
    /// Represents symmetric block cipher created by Bruce Schneier
    /// </summary>
    public class Twofish : BlockCipher
    {
        /// <summary>
        /// Creates new instance of the Twofish cipher. 
        /// </summary>
        /// <param name="key">Secret bytes, length </param>
        /// <param name="inputBlockLength"></param>
        public Twofish(byte[] key) : base(key, 128)
        {

        }

        public override long Decrypt(byte[] buffer, long offset, byte[] outputBuffer, long outputOffset, long length)
        {
            throw new System.NotImplementedException();
        }

        public override long Encrypt(byte[] buffer, long offset, byte[] outputBuffer, long outputOffset, long length)
        {
            throw new System.NotImplementedException();
        }
    }
}
