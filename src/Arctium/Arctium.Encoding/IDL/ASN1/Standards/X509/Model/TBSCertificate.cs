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
        public AlgorithmIdentifier Signature;
        public AttributeTypeAndValue[] Issuer;
        public Validity Validity;
        public AttributeTypeAndValue[] Subject;
        public SubjectPublicKeyInfo SubjectPublicKeyInfo;
        public Extension[] Extensions;
    }
}
