using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    public interface IExtensionDecoder
    {
        CertificateExtension DecodeExtension(ExtensionModel model);
    }
}
