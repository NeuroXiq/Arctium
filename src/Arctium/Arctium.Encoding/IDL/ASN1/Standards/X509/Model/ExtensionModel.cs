using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using ASN1 = Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;


namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Model
{
    public class ExtensionModel
    {
        public ObjectId ExtId;
        public ASN1::Boolean Critical;
        public OctetString ExtnValue;

        public ExtensionModel(ObjectId extId, ASN1::Boolean critical, OctetString extnValue)
        {
            ExtId = extId;
            Critical = critical;
            ExtnValue = extnValue;
        }
    }
}
