using System;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID
{
    /// <summary>
    /// Some prefixes of OID values are static and common across
    /// x509 structures. This simple builder provides methods creates <br/>
    /// this common OID structures with last number as a parameter
    /// </summary>
    public class X509CommonOidsBuilder
    {
        public static ObjectIdentifier idpkix(ulong last)
        {
            return new ObjectIdentifier(1, 3, 6, 1, 5, 5, 7, last);
        }

        public static ObjectIdentifier idpe(ulong last)
        {
            return new ObjectIdentifier(1, 3, 6, 1, 5, 5, 7, 1, last);
        }

        internal static ObjectIdentifier idad(ulong last)
        {
            return new ObjectIdentifier(1, 3, 6, 1, 5, 5, 7, 48, last);
        }

        public static ObjectIdentifier idce(ulong last)
        {
            return new ObjectIdentifier(2, 5, 29, last);
        }

        public static ObjectIdentifier pkcs1(ulong last)
        {
            return new ObjectIdentifier(1, 2, 840, 113549, 1, 1, last);
        }
    }
}
