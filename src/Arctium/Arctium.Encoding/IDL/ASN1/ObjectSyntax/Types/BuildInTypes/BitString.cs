using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public class BitString : Asn1TaggedType, IAsn1StrictType<BitStringValue>
    {
        private readonly static Tag tag = BuildInTag.Bitstring;

        public BitString(BitStringValue value) : base(tag, value) { }

        public BitStringValue TypedValue { get; set; }

        public override object Value { get { return TypedValue; } set { SetAsStrict(value); } }

        public void SetAsStrict(object value)
        {
            if(!(value is BitStringValue))
                throw InvalidStrictTypeException.Create<BitString, BitStringValue>(value);

            TypedValue = (BitStringValue)value;
        }
    }
}
