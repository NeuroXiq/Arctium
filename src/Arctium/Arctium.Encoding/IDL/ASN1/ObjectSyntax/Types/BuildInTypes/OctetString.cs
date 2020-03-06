using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public class OctetString : Asn1TaggedType, IAsn1StrictType<byte[]>
    {
        public OctetString(object value) : base(BuildInTag.Octetstring, value)
        {
        }

        public override object Value { get { return TypedValue; } set { SetAsStrict(value); } }

        public byte[] TypedValue { get; set; }

        public void SetAsStrict(object value)
        {
            if (!(value is byte[]))
            {
                throw InvalidStrictTypeException.Create<OctetString, byte[]>(value);
            }

            TypedValue = (byte[])value;
        }
    }
}
