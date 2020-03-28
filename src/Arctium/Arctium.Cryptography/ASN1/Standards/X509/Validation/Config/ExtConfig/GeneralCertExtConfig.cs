using System;
using Arctium.Cryptography.ASN1.Standards.X509.X509Cert;

namespace Arctium.Cryptography.ASN1.Standards.X509.Validation.Config.ExtConfig
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
