using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types;
using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Encoding.IDL.ASN1.Standards.X509.Types
{
    public class Version : Asn1TaggedType, IAsn1StrictType<Integer>
    {
        public Version(object value) : base(new Tag(TagClass.Private, 0), value) { }

        public override object Value { get { return TypedValue; } set { SetAsStrict(value); } }

        public Integer TypedValue { get; set; }

        public void SetAsStrict(object value)
        {
            if (!(value is Integer))
            {
                throw InvalidStrictTypeException.Create<Version, IAsn1StrictType<Integer>>(value);
            }

            TypedValue = (Integer)value;
        }
    }
}
