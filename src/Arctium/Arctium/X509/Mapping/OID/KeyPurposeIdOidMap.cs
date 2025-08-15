using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.X509.X509Cert.Extensions;
using System.Collections.Generic;
using Arctium.Standards.ASN1.Shared;
using Arctium.Shared;

namespace Arctium.Standards.ASN1.Standards.X509.Mapping.OID
{
    /// <summary>
    /// Creates mapping from <see cref="ObjectIdentifier"/> to <see cref="KeyPurposeId"/> enumerated type
    /// </summary>
    public class KeyPurposeIdOidMap
    {
        const string MapName = nameof(KeyPurposeIdOidMap);

        public static ObjectIdentifier Get(KeyPurposeId keyPurposeId)
        {
            if (!map.ContainsKey(keyPurposeId))
            {
                throw new KeyNotFoundException($"{MapName}: " +
                    $"Map from {keyPurposeId.ToString()} to OID not found ");
            }

            return map[keyPurposeId];
        }


        public static KeyPurposeId Get(ObjectIdentifier oid)
        {
            if (!map.ContainsKey(oid))
            {
                return KeyPurposeId.UNKNOW_NotImplemented;
            }

            return map[oid];
        }

        static ObjectIdentifier idkp(ulong last)
        {
            return new ObjectIdentifier(1,3,6,1,5,5,7,3, last);
        }

        static DoubleDictionary<ObjectIdentifier, KeyPurposeId> map = new DoubleDictionary<ObjectIdentifier, KeyPurposeId>()
        {
            [KeyPurposeId.AnyExtendedKeyUsage] = new ObjectIdentifier(2, 5, 29, 37, 0),
            [KeyPurposeId.ServerAuth] = idkp(1),
            [KeyPurposeId.ClientAuth] = idkp(2),
            [KeyPurposeId.CodeSigning] = idkp(3),
            [KeyPurposeId.EmailProtection] = idkp(4),
            [KeyPurposeId.TimeStamping] = idkp(8),
            [KeyPurposeId.OCSPSigning] = idkp(9)
        };
    }
}
