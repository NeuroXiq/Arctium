namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    /// <summary>
    /// Represents Diffie-Hellman key exchange (dhpublicnumber) algorithm parameters.
    /// </summary>
    public struct DomainParameters
    {
        /// <summary>
        /// Odd prime , p=jq+1
        /// </summary>
        public byte[] P;
        /// <summary>
        /// generator
        /// </summary>
        public byte[] G;
        /// <summary>
        /// factor of p-1
        /// </summary>
        public byte[] Q;
        /// <summary>
        /// OPTIONAL, subgroup factor
        /// </summary>
        public byte[] J;

        //optional

        /// <summary>
        /// Seed lenght in bits
        /// </summary>
        public int SeedLength;
        /// <summary>
        /// OPTIONAL
        /// </summary>
        public byte[] Seed;
        /// <summary>
        /// OPTIONAL
        /// </summary>
        public byte[] PGenCounter;
    }
}
