using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Standards.ASN1.Standards.X509.Model
{
    public class PublicKeyInfoModel
    {
        public AlgorithmIdentifierModel Algorithm;
        public BitString SubjectPublicKey;

        public PublicKeyInfoModel(AlgorithmIdentifierModel algorithmIdentifier, BitString subjectPublicKey)
        {
            Algorithm = algorithmIdentifier;
            SubjectPublicKey = subjectPublicKey;
        }
    }
}
