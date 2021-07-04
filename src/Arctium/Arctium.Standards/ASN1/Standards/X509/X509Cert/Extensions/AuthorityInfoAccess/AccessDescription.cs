

namespace Arctium.Standards.ASN1.Standards.X509.X509Cert.Extensions
{
    /// <summary>
    /// Represents X509 AccessDescription structure. Consists of access method and location.
    /// Indicates how to access services and informations for issuer of the certificate.
    /// </summary>
    public class AccessDescription
    {
        public AccessMethodType AccessMethod { get; private set; }
        public GeneralName AccessLocation { get; private set; }

        public AccessDescription(AccessMethodType accessMethodType, GeneralName accessLocation)
        {
            AccessMethod = accessMethodType;
            AccessLocation = accessLocation;
        }
    }
}
