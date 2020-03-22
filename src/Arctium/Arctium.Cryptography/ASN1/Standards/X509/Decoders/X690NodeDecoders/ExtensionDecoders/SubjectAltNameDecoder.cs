using Arctium.Cryptography.ASN1.Serialization.X690.DER;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.Types;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;
using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    public class SubjectAltNameDecoder : IExtensionDecoder
    {
        DerDeserializer derDeserializer = new DerDeserializer();
        public CertificateExtension DecodeExtension(ExtensionModel arg)
        {
            var sequence = derDeserializer.Deserialize(arg.ExtnValue)[0];

            GeneralName[] generalNames = ExtensionsDecoder.DecodeGeneralNames(sequence);

            return new SubjectAlternativeNamesExtension(arg.Critical, generalNames);
        }
    }
}
