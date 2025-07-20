namespace Arctium.Standards.ASN1.ObjectSyntax.Types
{
    public struct TaggedType<TType>
    {
        public TType Value { get; private set; }
        public Tag[] Tags { get; private set; }

        public TaggedType(TType value, Tag[] tags)
        {
            Value = value;
            Tags = tags;
        }
    }
}
