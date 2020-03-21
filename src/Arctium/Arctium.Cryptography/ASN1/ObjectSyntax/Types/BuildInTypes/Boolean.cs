using ASN = Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Cryptography.ASN1.ObjectSyntax.Types.BuildInTypes
{
    public struct Boolean
    {
        public bool Value;
        public Boolean(bool boolValue)
        {
            Value = boolValue;
        }

        public static implicit operator bool(ASN.Boolean boolean) => boolean.Value;
        public static implicit operator ASN.Boolean(bool value) => new ASN.Boolean(value);
    }
}
