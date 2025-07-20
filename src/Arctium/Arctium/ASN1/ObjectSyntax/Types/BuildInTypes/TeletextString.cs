namespace Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public struct TeletextString
    {
        public string Value { get; private set; }

        public TeletextString(string value)
        {
            Value = value;
        }
    }
}
