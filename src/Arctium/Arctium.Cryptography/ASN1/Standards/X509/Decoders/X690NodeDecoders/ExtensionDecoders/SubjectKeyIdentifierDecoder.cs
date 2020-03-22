using System;
using System.Collections.Generic;
using System.Text;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    public class SubjectKeyIdentifierDecoder : IExtensionDecoder
    {
        static DerDeserializer derDeserializer = new DerDeserializer();
        public CertificateExtension DecodeExtension(ExtensionModel model)
        {
            return Decode(model);
        }

        public static CertificateExtension Decode(ExtensionModel arg)
        {
            var node = derDeserializer.Deserialize(arg.ExtnValue)[0];
            byte[] value = DerDecoders.DecodeWithoutTag<OctetString>(node);

            return new SubjectKeyIdentifierExtension(arg.Critical, value);
        }
    }
}
