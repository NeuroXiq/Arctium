using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Model;

using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    public class AuthorityKeyIdentifierDecoder : IExtensionDecoder
    {
        DerDeserializer derDeserializer = new DerDeserializer();
        public CertificateExtension DecodeExtension(ExtensionModel model)
        {
            // all fields optional
            byte[] data = model.ExtnValue;

            X690DecodedNode node = derDeserializer.Deserialize(data)[0];

            byte[] keyIdentifier = null;
            GeneralName[] generalNames = null;
            byte[] certSerialNum = null;

            int next = 0;

            // TODO X509/ExtensionDecoder order of items can be incorrect.
            // e.g. context-specific node [2] can be before context-specific node [1]
            // create validator for X690 for decoded node in X690 folder

            //all implicit tags

            if (node.HaveCS(0))
            {
                var keyIdentNode = node.GetCSNode(0);
                keyIdentifier = DerDecoders.DecodeWithoutTag<OctetString>(keyIdentNode);
            }
            if (node.HaveCS(1))
            {
                generalNames = ExtensionsDecoder.DecodeGeneralNames(node.GetCSNode(1)[0]);
            }
            if (node.HaveCS(2))
            {
                certSerialNum = DerDecoders.DecodeWithoutTag<Integer>(node.GetCSNode(2)).BinaryValue;
            }

            return new AuthorityKeyIdentifierExtension(model.Critical.Value, generalNames, keyIdentifier, certSerialNum);

        }
    }
}
