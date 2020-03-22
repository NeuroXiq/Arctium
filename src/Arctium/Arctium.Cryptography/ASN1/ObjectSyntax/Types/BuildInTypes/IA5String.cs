namespace Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public struct IA5String
    {
        public string Value;
        public IA5String(string value)
        {
            Value = value;
        }

        public static implicit operator string(IA5String ia5String) => ia5String.Value;
        public static implicit operator IA5String(string value) => new IA5String(value);
    }
}
