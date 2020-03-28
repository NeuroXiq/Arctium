namespace Arctium.Cryptography.ASN1.Standards.X509.X509Cert.Extensions
{
    public class CertificatePoliciesExtension : CertificateExtension
    {
        public PolicyInformation[] PolicyInformations { get; private set; }
        public CertificatePoliciesExtension(PolicyInformation[] policyInformations, bool isCritical) : base(ExtensionType.CertificatePolicy, isCritical)
        {
            this.PolicyInformations = policyInformations;
        }
    }
}
