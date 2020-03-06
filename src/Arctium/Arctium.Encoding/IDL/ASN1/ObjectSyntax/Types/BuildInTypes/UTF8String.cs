using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public class UTF8String : Asn1TaggedType, IAsn1StrictType<string>
    {        
        public override object Value { get { return TypedValue; } set { SetAsStrict(value); } }
        public string TypedValue { get; set; }

        public UTF8String(string value) : base(BuildInTag.UTF8String, value)
        {
        }

        public void SetAsStrict(object value)
        {
            if (!(value is string))
            {
                throw InvalidStrictTypeException.Create<UTF8String, string>(value);
            }

            TypedValue = (string)value;
        }
    }
}
