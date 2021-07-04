using System;
using Arctium.Standards.ASN1.Standards.X509.X509Cert;
using Arctium.Standards.ASN1.Standards.X509.X509Cert.Extensions;

namespace Arctium.Standards.ASN1.Standards.X509.Validation.Config.ExtConfig
{
    public struct GeneralCertExtConfig
    {
        public ExtensionType[] MustNotBe;
        public ExtensionType[] MustBe;

        public static GeneralCertExtConfig Default()
        {
            throw new NotImplementedException();
        }
    }
}
