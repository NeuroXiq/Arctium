using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Standards.ASN1.Standards.X509.Model
{
    public class SubjectPublicKeyInfoModel
    {
        public AlgorithmIdentifierModel Algorithm;
        public BitString SubjectPublicKey;

        public SubjectPublicKeyInfoModel(AlgorithmIdentifierModel algorithmIdentifier, BitString subjectPublicKey)
        {
            Algorithm = algorithmIdentifier;
            SubjectPublicKey = subjectPublicKey;
        }
    }
}
