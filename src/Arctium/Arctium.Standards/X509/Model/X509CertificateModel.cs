using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Standards.ASN1.Standards.X509.Model
{
    /// <summary>
    /// Model gives conventient way to: create, manipulate and serializate certificate.
    /// For typical, high level usage, X509Certifiate should be used.
    /// </summary>
    public class X509CertificateModel
    {
        public TBSCertificate TBSCertificate;
        public AlgorithmIdentifierModel SignatureAlgorithm;
        public BitString SignatureValue;

        public X509CertificateModel(TBSCertificate tbsCertificate, AlgorithmIdentifierModel algorithmIdentifier, BitString signatureValue)
        {
            TBSCertificate = tbsCertificate;
            SignatureAlgorithm = algorithmIdentifier;
            SignatureValue = signatureValue;
        }
    }
}
