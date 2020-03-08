using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;
using ASN1 = Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;


namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Model
{
    public class Extension
    {
        private ObjectIdentifier ExtId;
        private ASN1::Boolean Critical;
        private OctetString ExtnValue;

        public Extension(ObjectIdentifier extId, ASN1::Boolean critical, OctetString extnValue)
        {
            ExtId = extId;
            Critical = critical;
            ExtnValue = extnValue;
        }
    }
}
