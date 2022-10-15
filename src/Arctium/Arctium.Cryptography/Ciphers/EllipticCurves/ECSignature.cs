using System.Numerics;

namespace Arctium.Cryptography.Ciphers.EllipticCurves
{
    public struct ECSignature
    {
        public BigInteger R;
        public BigInteger S;

        public ECSignature(BigInteger r, BigInteger s) : this()
        {
            this.R = r;
            this.S = s;
        }
    }
}
