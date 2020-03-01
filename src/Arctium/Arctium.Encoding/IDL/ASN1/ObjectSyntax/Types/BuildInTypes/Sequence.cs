using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;
using System.Collections.Generic;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public class Sequence : Asn1TaggedType, IAsn1StrictType<List<Asn1TaggedType>>
    {
        public override object Value { get { return TypedValue; } set { SetAsStrict(value); } }
        public List<Asn1TaggedType> TypedValue { get; set; }


        private static readonly Tag tag = BuildInTag.Sequence;


        public Sequence(object value) : base(tag)
        {
            SetAsStrict(value);
        }

        public void SetAsStrict(object value)
        {
            bool isValid = (value is List<Asn1TaggedType>) && value != null;

            if (isValid)
            {
                TypedValue = (List<Asn1TaggedType>)value;
            }
            else
            {
                throw InvalidStrictTypeException.Create<IAsn1StrictType<int>, IAsn1StrictType<int>>(null);
            }
        }
    }
}
