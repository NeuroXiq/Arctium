

/*
 * Map from bytes inside Asn1 object to defined public key object
 * 
 * Performs mapping.
 * 
 * Public key is internally represented as a byte array but this class creates
 * concrete object from public key bytes.
 * e.g. 
 * encoded RSA public key is some byte array but should be represented as obj = { N = 123123..., E=345234 .. } 
 */

using System;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.Standards.X509.Mapping
{
    public class PublicKeyMapper
    {
        static PublicKeyMapper()
        {
            Initialize();
        }

        private static void Initialize()
        {

        }

        internal object Map(ObjectIdentifier oid, BitString value)
        {
            return null;
        }
    }
}
