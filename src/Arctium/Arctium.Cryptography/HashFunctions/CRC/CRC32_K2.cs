namespace Arctium.Cryptography.HashFunctions.CRC
{
    /// <summary>
    /// Implementation of CRC-32 K (Koopman {1,1,30})
    /// </summary>
    public class CRC32_K2 : CRC32
    {
        public const uint Polynomial = 0x32583499;

        /// <summary>
        /// Initializes new instance of CRC32_C (castagnoli)
        /// </summary>
        public CRC32_K2() : base(Polynomial)
        {
        }
    }
}
