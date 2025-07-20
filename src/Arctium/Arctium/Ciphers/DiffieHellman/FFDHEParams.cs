using System.Numerics;

namespace Arctium.Cryptography.Ciphers.DiffieHellman
{
    public class FFDHEParams
    {
        /// <summary>
        /// Modulus (big endian)
        /// </summary>
        public BigInteger P { get; private set; }

        /// <summary>
        /// The group size q = (p-1)/2
        /// </summary>
        public BigInteger Q { get; private set; }

        /// <summary>
        /// Generator point
        /// </summary>
        public BigInteger G { get; private set; }

        public FFDHEParams(BigInteger p, BigInteger q, BigInteger g)
        {
            P = p;
            Q = q;
            G = g;
        }
    }
}
