using Arctium.Standards.ArctiumLibShared;
using System.Numerics;

namespace Arctium.Standards.EllipticCurves.SEC1
{
    public struct ECSignature : IArctiumConvertable<ArctiumLibShared.ECSignature>
    {
        public BigInteger R;
        public BigInteger S;

        /// <summary>
        /// Creates signature with specified ECC signature values represented as byte array.
        /// Byte arrays are parsed as signed, big endian integers
        /// </summary>
        /// <param name="r"></param>
        /// <param name="s"></param>
        public ECSignature(byte[] r, byte[] s)
        {
            this.R = new BigInteger(r, true, true);
            this.S = new BigInteger(s, true, true);
        }

        public ECSignature(BigInteger r, BigInteger s) : this()
        {
            this.R = r;
            this.S = s;
        }

        public ArctiumLibShared.ECSignature Convert()
        {
            return new ArctiumLibShared.ECSignature(R, S);
        }
    }
}
