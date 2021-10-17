using System;
using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.ASN1.Standards.X509.Model;
using Arctium.Standards.X509.X509Cert.Extensions;

namespace Arctium.Standards.ASN1.Standards.X509.Decoders.X690Decoders.Extensions
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
