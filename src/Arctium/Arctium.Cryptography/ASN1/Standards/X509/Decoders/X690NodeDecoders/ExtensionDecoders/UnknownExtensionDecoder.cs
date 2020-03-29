using System;
using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X509.Model;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions;

namespace Arctium.Cryptography.ASN1.Standards.X509.Decoders.X690NodeDecoders.ExtensionDecoders
{
    public class UnknownExtensionDecoder : IExtensionDecoder
    {
        public CertificateExtension DecodeExtension(ExtensionModel model)
        {
            byte[] extValue = model.ExtnValue.Value;
            ObjectIdentifier oid = model.ExtId;
            bool critical = model.Critical;

            return new UnknownExtension(extValue, oid, critical);
        }
    }
}
