namespace Arctium.Cryptography.HashFunctions.CRC
{
    /// <summary>
    /// Implementation of CRC-32 K (Koopman {1,1,30})
    /// </summary>
    public class CRC32_Q : CRC32
    {
        public const uint Polynomial = 0x814141AB;

        /// <summary>
        /// Initializes new instance of CRC32_C (castagnoli)
        /// </summary>
        public CRC32_Q() : base(Polynomial, 0, false, false, 0)
        {
        }
    }
}
