namespace Arctium.Cryptography.ASN1.Serialization
{
    public abstract class ASN1Serializer
    {
        public Asn1EncodingRule EncodingRules { get; private set; }

        public ASN1Serializer(Asn1EncodingRule rules)
        {
            this.EncodingRules = rules;
        }

        public abstract long Serialize(object input);

        public abstract object Deserialize(int input);
    }
}
