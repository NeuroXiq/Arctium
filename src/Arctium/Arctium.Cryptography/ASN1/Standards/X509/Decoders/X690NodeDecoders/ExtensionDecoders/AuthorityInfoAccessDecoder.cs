using System.Collections.Generic;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Mapping.OID;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.Types;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    public class AuthorityInfoAccessDecoder : IExtensionDecoder
    {
        DerDeserializer derDeserializer = new DerDeserializer();
        X690Validation validation = new X690Validation(nameof(AuthorityInfoAccessDecoder));
        public CertificateExtension DecodeExtension(ExtensionModel model)
        {
            var accessDescriptionSequence = derDeserializer.Deserialize(model.ExtnValue.Value)[0];

            List<AccessDescription> decoded = new List<AccessDescription>();
            foreach (var accessDescriptionNode in accessDescriptionSequence)
                decoded.Add(DecodeAccessDescription(accessDescriptionNode));

            return new AuthorityInfoAccessExtension(decoded.ToArray(), model.Critical);
        }

        public AccessDescription DecodeAccessDescription(X690DecodedNode node)
        {
            validation.CLength(node, 2);
            validation.Tag(node[0], BuildInTag.ObjectIdentifier);

            var oidNode = node[0];
            var generalNameNode = node[1];

            ObjectIdentifier methodOid = DerDecoders.DecodeWithoutTag<ObjectIdentifier>(oidNode);

            AccessMethodType accessMethodType = AccessMethodTypeOidMap.Get(methodOid);
            GeneralName generalName = ExtensionsDecoder.DecodeGeneralName(generalNameNode);

            return new AccessDescription(accessMethodType, generalName);
        }
    }
}
