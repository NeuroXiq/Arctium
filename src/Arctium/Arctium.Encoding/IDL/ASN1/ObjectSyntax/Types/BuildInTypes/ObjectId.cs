using Arctium.Encoding.IDL.ASN1.ObjectSyntax.Exceptions;

namespace Arctium.Encoding.IDL.ASN1.ObjectSyntax.Types.BuildInTypes
{
    /// <summary>
    /// Represents ASN.1 Object Identifier Tagged type with <see cref="ObjectIdentifier"/>
    /// as an strict type
    /// </summary>
    public class ObjectId : Asn1TaggedType, IAsn1StrictType<ObjectIdentifier>
    {
        public ObjectIdentifier TypedValue { get; set; }

        public override object Value { get { return TypedValue;} set { SetAsStrict(value); } }

        public void SetAsStrict(object value)
        {
            if (!(value is ObjectIdentifier))
                throw InvalidStrictTypeException.Create<ObjectId, ObjectIdentifier[]>(value);

            TypedValue = (ObjectIdentifier)value;
        }

        public ObjectId() : base(BuildInTag.ObjectIdentifier)
        {

        }

        public ObjectId(ObjectIdentifier value) : base(BuildInTag.ObjectIdentifier)
        {
            this.TypedValue = value;
        }

        public override string ToString()
        {
            return TypedValue.ToString();
        }

        public override bool Equals(object obj)
        {
            return this.TypedValue.Equals(obj);
        }
    }
}
