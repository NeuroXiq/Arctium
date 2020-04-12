using System;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
{
    public class SCTLDecoder : IExtensionDecoder
    {
        public CertificateExtension DecodeExtension(ExtensionModel model)
        {
            return new SCTLExtension(model.ExtnValue, model.Critical);
        }
    }
}
