using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public class Null : Asn1TaggedType, IAsn1StrictType<object>
    {
        private static readonly Tag tag = BuildInTag.Null;
        public Null() : base(tag)
        {
        }

        public object TypedValue { get { return null; } set { SetAsStrict(value); } }

        public override object Value { get { return TypedValue; } set { TypedValue = value; } }

        public void SetAsStrict(object value)
        {
            if(value != null)
                throw new InvalidStrictTypeException("For 'Null' ASN.1 expected null value", "Null", null, value.GetType().Name);
        }
    }
}
