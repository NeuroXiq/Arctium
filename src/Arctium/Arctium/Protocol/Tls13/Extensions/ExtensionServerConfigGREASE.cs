namespace Arctium.Protocol.Tls13.Extensions
{
    public class ExtensionServerConfigGREASE
    {
        public int CertificateRequestSignatureAlgorithmsCount { get; private set; }
        public int CertificateRequestSignatureAlgorithmsCertCount { get; private set; }
        public int CertificateRequestExtensionsCount { get; private set; }
        public int NewSessionTicketExtensionsCount { get; private set; }

        public ExtensionServerConfigGREASE(
            int certReqSignatureAlgorithmsCount = 3,
            int certReqSignatureAlgorithmsCertCount = 3,
            int certReqExtensionsCountInCertRequest = 3,
            int newSessTickExtCount = 3)
        {
            CertificateRequestSignatureAlgorithmsCount = certReqSignatureAlgorithmsCount;
            CertificateRequestSignatureAlgorithmsCertCount = certReqSignatureAlgorithmsCertCount;
            CertificateRequestExtensionsCount = certReqExtensionsCountInCertRequest;
            NewSessionTicketExtensionsCount = newSessTickExtCount;
        }
    }
}
