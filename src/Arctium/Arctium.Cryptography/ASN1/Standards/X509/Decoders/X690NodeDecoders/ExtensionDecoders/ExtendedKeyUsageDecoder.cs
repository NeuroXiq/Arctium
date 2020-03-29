using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;
using System.Collections.Generic;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    class ExtendedKeyUsageDecoder : IExtensionDecoder
    {
        DerDeserializer derDeserializer = new DerDeserializer();

        public CertificateExtension DecodeExtension(ExtensionModel arg)
        {
            var sequence = derDeserializer.Deserialize(arg.ExtnValue.Value)[0];

            List<KeyPurposeId> keyPurposes = new List<KeyPurposeId>();

            foreach (var oidNode in sequence)
            {
                ObjectIdentifier extKeyUsageOid = DerDecoders.DecodeWithoutTag<ObjectIdentifier>(oidNode);
                KeyPurposeId mapped = KeyPurposeIdOidMap.Get(extKeyUsageOid);
                keyPurposes.Add(mapped);
            }

            return new ExtendedKeyUsageExtension(arg.Critical, keyPurposes.ToArray());
        }
    }
}
