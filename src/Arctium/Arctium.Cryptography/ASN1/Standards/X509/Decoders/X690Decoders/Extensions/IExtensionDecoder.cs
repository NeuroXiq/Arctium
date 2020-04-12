using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
{
    interface IExtensionDecoder
    {
        CertificateExtension DecodeExtension(ExtensionModel model);
    }
}
