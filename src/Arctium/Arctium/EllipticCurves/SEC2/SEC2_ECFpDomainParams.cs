using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.EllipticCurves.SEC2
{
    public class SEC2_ECFpDomainParams
    {
        /// <summary>
        /// Finit field Fp
        /// </summary>
        public byte[] p;

        /// <summary>
        /// Specified in elliptic curve equation 
        /// y^2 = x^3 + ax + b
        /// </summary>
        public byte[] a;

        /// <summary>
        /// Specified in elliptic curve equation 
        /// y^2 = x^3 + ax + b
        /// </summary>
        public byte[] b;

        /// <summary>
        /// Base point G
        /// </summary>
        public byte[] G;

        /// <summary>
        /// Prime n order of G
        /// </summary>
        public byte[] n;

        /// <summary>
        /// Cofactor
        /// </summary>
        public byte[] h;

        public SEC2_ECFpDomainParams(byte[] p, byte[] a, byte[] b, byte[] g, byte[] n, byte[] h)
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
