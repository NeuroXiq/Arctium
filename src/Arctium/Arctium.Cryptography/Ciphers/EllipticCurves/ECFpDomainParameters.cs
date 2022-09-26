using System.Numerics;

namespace Arctium.Cryptography.Ciphers.EllipticCurves
{
    public class ECFpDomainParameters
    {
        /// <summary>
        /// Finit field Fp
        /// </summary>
        public BigInteger p;

        /// <summary>
        /// Specified in elliptic curve equation 
        /// y^2 = x^3 + ax + b
        /// </summary>
        public BigInteger a;

        /// <summary>
        /// Specified in elliptic curve equation 
        /// y^2 = x^3 + ax + b
        /// </summary>
        public BigInteger b;

        /// <summary>
        /// Base point G
        /// </summary>
        public ECFpPoint G;

        /// <summary>
        /// Prime n order of G
        /// </summary>
        public BigInteger n;

        /// <summary>
        /// Cofactor
        /// </summary>
        public BigInteger h;

        public ECFpDomainParameters(BigInteger p, BigInteger a, BigInteger b, ECFpPoint g, BigInteger n, BigInteger h)
        {
            this.p = p;
            this.a = a;
            this.b = b;
            G = g;
            this.n = n;
            this.h = h;
        }
    }
}
