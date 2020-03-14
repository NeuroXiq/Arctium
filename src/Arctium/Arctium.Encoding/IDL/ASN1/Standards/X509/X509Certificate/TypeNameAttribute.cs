namespace Arctium.Encoding.IDL.ASN1.Standards.X509.X509Certificate
{
    public struct TypeNameAttribute
    {
        public string Type { get; private set; }
        public string Value { get; private set; }

        public TypeNameAttribute(string type, string value)
        {
            Type = type;
            Value = value;
        }
    }
}
