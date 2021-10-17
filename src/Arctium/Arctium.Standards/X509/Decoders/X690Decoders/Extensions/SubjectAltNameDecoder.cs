using Arctium.Standards.ASN1.Serialization.X690v2.DER;
using Arctium.Standards.ASN1.Serialization.X690v2.DER.BuildInTypeDecoders;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.X509.X509Cert;
using Arctium.Standards.X509.X509Cert.Extensions;

namespace Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
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
