namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    public class PublicKeyAlgorithmIdentifier
    {
        public PublicKeyAlgorithmIdentifierType Algorithm { get; private set; }
        public PublicKeyAlgorithmIdentifierParameters Parameters { get; private set; }

        public PublicKeyAlgorithmIdentifier(PublicKeyAlgorithmIdentifierType type, PublicKeyAlgorithmIdentifierParameters parms)
        {
            Algorithm = type;
            Parameters = parms;
        }
    }
}
