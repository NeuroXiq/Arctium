using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Model
{
    public class SubjectPublicKeyInfo
    {
        public AlgorithmIdentifier Algorithm;
        public BitString SubjectPublicKey;

        public SubjectPublicKeyInfo(AlgorithmIdentifier algorithmIdentifier, BitString subjectPublicKey)
        {
            Algorithm = algorithmIdentifier;
            SubjectPublicKey = subjectPublicKey;
        }
    }
}
