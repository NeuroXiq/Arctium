namespace Arctium.Cryptography.HashFunctions.CRC
{
    /// <summary>
    /// Implementation of CRC-32 C (Castagnoli)
    /// </summary>
    public class CRC32_C : CRC32
    {
        public const uint Polynomial = 0x1EDC6F41;

        /// <summary>
        /// Initializes new instance of CRC32_C (castagnoli)
        /// </summary>
        public CRC32_C() : base(Polynomial)
        {
        }
    }
}
