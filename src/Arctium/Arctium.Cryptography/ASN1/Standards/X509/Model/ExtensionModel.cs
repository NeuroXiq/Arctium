using Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;
using ASN1 = Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;


namespace Arctium.Cryptography.ASN1.Standards.X509.Model
{
    public class ExtensionModel
    {
        public ObjectIdentifier ExtId;
        public ASN1::Boolean Critical;
        public OctetString ExtnValue;

        public ExtensionModel(ObjectIdentifier extId, ASN1::Boolean critical, OctetString extnValue)
        {
            ExtId = extId;
            Critical = critical;
            ExtnValue = extnValue;
        }
    }
}
