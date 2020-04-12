using Arctium.Cryptography.ASN1.Serialization.X690v2.DER;
using Arctium.Cryptography.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
{
    public class SubjectAltNameDecoder : IExtensionDecoder
    {
        public CertificateExtension DecodeExtension(ExtensionModel arg)
        {
            var sequence = DerDeserializer.Deserialize(arg.ExtnValue, 0);
            var decoder = new DerTypeDecoder(arg.ExtnValue.Value);

            GeneralName[] generalNames = ExtensionsDecoder.DecodeGeneralNames(decoder, sequence);

            return new SubjectAlternativeNamesExtension(arg.Critical, generalNames);
        }
    }
}
