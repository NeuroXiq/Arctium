using Arctium.Cryptography.ASN1.Standards.X509.Validation.Config.ExtConfig;
using System;

namespace Arctium.Cryptography.ASN1.Standards.X509.Validation.Config
{
    public struct ExtensionsValidationConfig
    {
        public GeneralCertExtConfig generalCertExtConfig;
        public CertificatePoliciesConfig CertificatePolicies;

        public static ExtensionsValidationConfig Default()
        {
            ExtensionsValidationConfig config = new ExtensionsValidationConfig();

            config.generalCertExtConfig = GeneralCertExtConfig.Default();
            config.CertificatePolicies = CertificatePoliciesConfig.Default();

            return config;
        }
    }
}
