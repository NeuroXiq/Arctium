using Arctium.Cryptography.ASN1.Standards.X509.Validation.Config;

namespace Arctium.Cryptography.ASN1.Standards.X509.Validation
{
    public class ValidationConfig
    {
        public ExtensionsValidationConfig exensionsConfig;
        public static ValidationConfig Default()
        {
            ValidationConfig config = new ValidationConfig();

            config.exensionsConfig = ExtensionsValidationConfig.Default();

            return config;
        }
    }
}
