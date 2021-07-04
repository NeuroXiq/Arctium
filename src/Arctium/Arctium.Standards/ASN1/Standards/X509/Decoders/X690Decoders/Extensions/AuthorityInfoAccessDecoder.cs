using System.Collections.Generic;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Standards.ASN1.Standards.X509.Mapping.OID;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.ASN1.Standards.X509.X509Cert;
using Arctium.Standards.ASN1.Standards.X509.X509Cert.Extensions;

namespace Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
{
    public class AuthorityInfoAccessDecoder : IExtensionDecoder
    {
        public CertificateExtension DecodeExtension(ExtensionModel model)
        {
            var accessDescriptionSequence = DerDeserializer.Deserialize(model.ExtnValue.Value, 0);
            var decoder = new DerTypeDecoder(model.ExtnValue.Value);

            List<AccessDescription> decoded = new List<AccessDescription>();
            foreach (var accessDescriptionNode in accessDescriptionSequence)
                decoded.Add(DecodeAccessDescription(decoder, accessDescriptionNode));

            return new AuthorityInfoAccessExtension(decoded.ToArray(), model.Critical);
        }

        public AccessDescription DecodeAccessDescription(DerTypeDecoder decoder, DerDecoded decoded)
        {
            var oidNode = decoded[0];
            var generalNameNode = decoded[1];

            ObjectIdentifier methodOid = decoder.ObjectIdentifier(oidNode);

            AccessMethodType accessMethodType = AccessMethodTypeOidMap.Get(methodOid);
            GeneralName generalName = ExtensionsDecoder.DecodeGeneralName(decoder, generalNameNode);

            return new AccessDescription(accessMethodType, generalName);
        }
    }
}
