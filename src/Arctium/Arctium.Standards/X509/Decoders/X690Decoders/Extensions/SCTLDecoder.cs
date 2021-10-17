using System;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.X509.X509Cert;
using Arctium.Standards.X509.X509Cert.Extensions;

namespace Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
{
    public class SCTLDecoder : IExtensionDecoder
    {
        public CertificateExtension DecodeExtension(ExtensionModel model)
        {
            return new SCTLExtension(model.ExtnValue, model.Critical);
        }
    }
}
