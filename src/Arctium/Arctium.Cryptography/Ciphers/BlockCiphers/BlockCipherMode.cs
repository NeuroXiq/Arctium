namespace Arctium.Cryptography.Ciphers.BlockCiphers
{
    /// <summary>
    /// Block cipher mode of operations
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
        /// Propagating cipher block chaining
        /// </summary>
        PCBC,
        /// <summary>
        /// Counter
        /// </summary>
        CTR
    }
}
