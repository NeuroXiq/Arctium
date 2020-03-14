using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using Arctium.Encoding.IDL.ASN1.Standards.X501.Types;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Types;
using Arctium.Encoding.IDL.ASN1.Standards.X509.Types.Model;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Model
{
    public class TBSCertificate
    {
        public Version Version;
        public Integer SerialNumber;
        public AlgorithmIdentifierModel Signature;
        public AttributeTypeAndValue[] Issuer;
        public Validity Validity;
        public AttributeTypeAndValue[] Subject;
        public SubjectPublicKeyInfoModel SubjectPublicKeyInfo;
        public byte[] IssuerUniqueId;
        public byte[] SubjectUniqueId;
        public ExtensionModel[] Extensions;
    }
}
