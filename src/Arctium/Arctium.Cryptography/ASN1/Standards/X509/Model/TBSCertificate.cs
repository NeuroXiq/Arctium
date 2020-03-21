using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Cryptography.ASN1.Standards.X500.Types;
using Arctium.Cryptography.ASN1.Standards.X509.Types;

using X500 = Arctium.Cryptography.ASN1.Standards.X500.Types;

namespace Arctium.Cryptography.ASN1.Standards.X509.Model
{
    public class TBSCertificate
    {
        public Integer Version;
        public Integer SerialNumber;
        public AlgorithmIdentifierModel Signature;
        public X500::Name Issuer;
        public Validity Validity;
        public X500::Name Subject;
        public SubjectPublicKeyInfoModel SubjectPublicKeyInfo;
        public BitString IssuerUniqueId;
        public BitString SubjectUniqueId;
        public ExtensionModel[] Extensions;
    }
}
