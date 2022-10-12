namespace Arctium.Standards.X509.X509Cert.Algorithms
{
    public class AlgorithmIdentifier
    {
        public AlgorithmIdentifierType Algorithm { get; private set; }
        public AlgorithmIdentifierParameters Parameters { get; private set; }

        public AlgorithmIdentifier(AlgorithmIdentifierType type, AlgorithmIdentifierParameters parms)
        {
            Algorithm = type;
            Parameters = parms;
        }
    }
}
