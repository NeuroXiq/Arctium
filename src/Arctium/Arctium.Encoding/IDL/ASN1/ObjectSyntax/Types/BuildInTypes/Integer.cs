using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public class Integer : Asn1TaggedType, IAsn1StrictType<IntegerValue>
    {
        public IntegerValue TypedValue { get; set; }

        public override object Value { get { return TypedValue; } set { SetAsStrict(value); } }

        public Integer(IntegerValue value) : base(BuildInTag.Integer, value)
        {

        }

        

        public void SetAsStrict(object value)
        {
            if (!(value is IntegerValue))
            {
                throw InvalidStrictTypeException.Create<Integer, IntegerValue>(value);
            }

            TypedValue = (IntegerValue)value;
        }
    }
}
