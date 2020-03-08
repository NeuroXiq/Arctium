using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Model
{
    /// <summary>
    /// Model gives conventient way to :manipulate certificate, creation it and serializate it.
    /// For typical, high level usage, X509Certifiate should be used but this type is fine too.
    /// </summary>
    public class X509CertificateModel
    {
        public TBSCertificate TBSCertificate;
        public AlgorithmIdentifier SignatureAlgorithm;
        public BitString SignatureValue;

        public X509CertificateModel(TBSCertificate tbsCertificate, AlgorithmIdentifier algorithmIdentifier, BitString signatureValue)
        {
            TBSCertificate = tbsCertificate;
            SignatureAlgorithm = algorithmIdentifier;
            SignatureValue = signatureValue;
        }
    }
}
