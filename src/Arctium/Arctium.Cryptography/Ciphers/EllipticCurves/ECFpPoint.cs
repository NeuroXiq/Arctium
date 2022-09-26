using System.Numerics;

namespace Arctium.Cryptography.Ciphers.EllipticCurves
{
    public class ECFpPoint
    {
        public BigInteger X;
        public BigInteger Y;

        public ECFpPoint(BigInteger x, BigInteger y)
        {
            X = x;
            Y = y;
        }
    }
}
