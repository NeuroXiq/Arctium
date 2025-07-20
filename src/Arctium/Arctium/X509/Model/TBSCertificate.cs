using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Standards.X501.Types;


using X500 = Arctium.Standards.X501.Types;

namespace Arctium.Standards.ASN1.Standards.X509.Model
{
    public class TBSCertificate
    {
        public Integer Version;
        public Integer SerialNumber;
        public AlgorithmIdentifierModel Signature;
        public X500::Name Issuer;
        public Validity Validity;
        public X500::Name Subject;
        public PublicKeyInfoModel SubjectPublicKeyInfo;
        public BitString IssuerUniqueId;
        public BitString SubjectUniqueId;
        public ExtensionModel[] Extensions;
    }
}
