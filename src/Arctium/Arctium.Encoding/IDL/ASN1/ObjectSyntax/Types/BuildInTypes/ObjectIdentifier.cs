using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public class ObjectIdentifier : Asn1TaggedType, IAsn1StrictType<OidSubidentifier[]>
    {
        public OidSubidentifier[] TypedValue { get; set; }

        public override object Value { get { return TypedValue;} set { SetAsStrict(value); } }

        public void SetAsStrict(object value)
        {
            if (!(value is OidSubidentifier))
                throw InvalidStrictTypeException.Create<ObjectIdentifier, OidSubidentifier[]>(value);

            TypedValue = (OidSubidentifier[])value;
        }

        public ObjectIdentifier() : base(BuildInTag.ObjectIdentifier)
        {

        }

        public ObjectIdentifier(OidSubidentifier[] value) : base(BuildInTag.ObjectIdentifier)
        {
            this.TypedValue = value;
        }

        public override string ToString()
        {
            ulong secondComponent = TypedValue[0].Number % 40;
            ulong firstComponent = (TypedValue[0].Number - secondComponent) / 40;
            string first = firstComponent.ToString();

            string result = $"{firstComponent}.{secondComponent}";

            for (int i = 1; i < TypedValue.Length; i++)
            {
                result += $".{TypedValue[i].Number.ToString()}";
            }

            return result;
        }
    }
}
