namespace Arctium.Cryptography.HashFunctions.CRC
{
    /// <summary>
    /// Implementation of CRC-32 K (Koopman {1,3,28})
    /// </summary>
    public class CRC32_K : CRC32
    {
        public const uint Polynomial = 0x741B8CD7;

        /// <summary>
        /// Initializes new instance of CRC32_C (castagnoli)
        /// </summary>
        public CRC32_K() : base(Polynomial)
        {
        }
    }
}
