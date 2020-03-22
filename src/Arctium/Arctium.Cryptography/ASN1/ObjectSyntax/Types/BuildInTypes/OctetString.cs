namespace Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public struct OctetString
    {
        public byte[] Value;
        public OctetString(byte[] binaryValue)
        {
            Value = binaryValue;
        }

        public static implicit operator byte[](OctetString octetString) => octetString.Value;
        public static implicit operator OctetString(byte[] array) => new OctetString(array);
    }
}
