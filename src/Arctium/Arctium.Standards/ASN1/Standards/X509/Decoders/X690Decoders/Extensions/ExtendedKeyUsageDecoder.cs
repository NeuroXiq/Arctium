using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690.DER;
using Arctium.Standards.ASN1.Standards.X509.Mapping.OID;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.ASN1.Standards.X509.X509Cert;
using Arctium.Standards.ASN1.Standards.X509.X509Cert.Extensions;
using System.Collections.Generic;

namespace Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
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
