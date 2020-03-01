using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public class Set : Asn1TaggedType, IAsn1StrictType<List<Asn1TaggedType>>
    {
        public Set(List<Asn1TaggedType> value) : base(BuildInTag.Set)
        {

        }

        public List<Asn1TaggedType> TypedValue { get; set; }

        public override object Value { get { return TypedValue; } set { SetAsStrict(value); } }

        public void SetAsStrict(object value)
        {
            if (!(value is List<Asn1TaggedType>))
                throw InvalidStrictTypeException.Create<Set, List<Asn1TaggedType>>(value);

            TypedValue = (List<Asn1TaggedType>)value;
        }
    }
}
