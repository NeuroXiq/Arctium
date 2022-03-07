namespace Arctium.Cryptography.HashFunctions.CRC
{
    public class CRC64_ISO : CRC64
    {
        /// <summary>
        /// CRC64-ECMA 182 Polynomial
        /// </summary>
        public const ulong ECMA182Polynomial = 0x42F0E1EBA9EA3693;
        public const bool ECMA182ResultReflected = false;
        public const bool ECMA182InputReflected = false;
        public const ulong ECMA182InitialValue = 0;
        public const ulong ECMA182FinalXorValue = 0;

        public CRC64_ISO() : base(ECMA182Polynomial,
            ECMA182InputReflected,
            ECMA182ResultReflected,
            ECMA182InitialValue,
            ECMA182FinalXorValue)
        {
        }
    }
}
