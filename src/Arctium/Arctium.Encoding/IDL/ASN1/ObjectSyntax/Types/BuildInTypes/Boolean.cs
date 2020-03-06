using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public class Boolean : Asn1TaggedType, IAsn1StrictType<bool>
    {
        public Boolean(bool value) : base(BuildInTag.Boolean, value) { }
        public Boolean() : base(BuildInTag.Boolean) { }

        public override object Value { get { return TypedValue; } set { SetAsStrict(value); } }

        public bool TypedValue { get; set; }

        public void SetAsStrict(object value)
        {
            if (!(value is bool))
            {
                throw InvalidStrictTypeException.Create<Boolean, bool>(value);
            }

            TypedValue = (bool)value;
        }
    }
}
