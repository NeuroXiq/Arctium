namespace Arctium.Cryptography.Ciphers.BlockCiphers.Shared
{
    /// <summary>
    /// Block cipher modes of operations.
    /// </summary>
    public enum BlockCipherMode
    {
        /// <summary>
        /// Electronic code book.
        /// </summary>
        ECB,
        /// <summary>
        /// Cipher block chaining
        /// </summary>
        CBC,
        /// <summary>
        /// Cipher feedback
        /// </summary>
        CFB,
        /// <summary>
        /// Output feedback
        /// </summary>
        OFB,
        /// <summary>
        /// Counter
        /// </summary>
        CTR
    }
}
