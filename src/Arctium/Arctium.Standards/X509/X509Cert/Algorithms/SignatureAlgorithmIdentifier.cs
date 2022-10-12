namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    public class SignatureAlgorithmIdentifier
    {
        public SignatureAlgorithmParameters SignatureAlgorithmParameters { get; private set; }

        public SignatureAlgorithmType SignatureAlgorithmType { get; private set; }

        public SignatureAlgorithmIdentifier(SignatureAlgorithmType type, SignatureAlgorithmParameters parms)
        {
            SignatureAlgorithmParameters = parms;
            SignatureAlgorithmType = type;
        }
    }
}
