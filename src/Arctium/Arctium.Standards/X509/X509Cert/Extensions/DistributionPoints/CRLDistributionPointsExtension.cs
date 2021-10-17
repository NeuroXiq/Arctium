namespace Arctium.Standards.X509.X509Cert.Extensions
{
    public class CRLDistributionPointsExtension : CertificateExtension
    {
        /// <summary>
        /// Represents sequence of distribution point fields
        /// </summary>
        public DistributionPoint[] DistributionPoints { get; private set; }

        public CRLDistributionPointsExtension(bool isCritical, DistributionPoint[] distributionPoints) : base(ExtensionType.CRLDistributionPoints, isCritical)
        {
            DistributionPoints = distributionPoints;
        }
    }
}
