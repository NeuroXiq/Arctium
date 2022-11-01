using System;
using System.Collections.Generic;
using System.Text;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Serialization.X690.DER;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.X509.X509Cert;
using Arctium.Standards.X509.X509Cert.Extensions;

namespace Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
{
    public class SubjectKeyIdentifierDecoder : IExtensionDecoder
    {
        public CertificateExtension DecodeExtension(ExtensionModel model)
        {
            return Decode(model);
        }

        public static CertificateExtension Decode(ExtensionModel arg)
        {
            DerDeserializer derDeserializer = new DerDeserializer();
            var node = derDeserializer.Deserialize(arg.ExtnValue)[0];
            byte[] value = DerDecoders.DecodeWithoutTag<OctetString>(node);

            return new SubjectKeyIdentifierExtension(arg.Critical, value);
        }
    }
}
