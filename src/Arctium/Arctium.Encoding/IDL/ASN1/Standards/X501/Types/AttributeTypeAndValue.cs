using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Encoding.IDL.ASN1.Standards.X501.Types
{
    public class AttributeTypeAndValue
    {
        public ObjectIdentifier Type;
        Asn1TaggedType Value;

        public AttributeTypeAndValue(ObjectIdentifier type, Asn1TaggedType value)
        {
            Type = type;
            Value = value;
        }
    }
}
