using Arctium.Standards.ASN1.ObjectSyntax.Types.BuildInTypes;

namespace Arctium.Standards.ASN1.Standards.X501.Types
{
    /// <summary>
    /// Special, unknown attibute type/value where identifier is not mapped
    /// to inner enumerated type. RawBytes can be used for external decoding <br/>
    /// (if is recognized by implementaion)
    /// </summary>
    public class UnknownAttributeTypeAndValue
    {
        public ObjectIdentifier Identifier;
        /// <summary>
        /// Raw bytes of the attribute value of the unrecognized type.
        /// </summary>
        public byte[] RawBytes;

        public UnknownAttributeTypeAndValue(ObjectIdentifier typeOid, byte[] rawValue)
        {
            Identifier = typeOid;
            RawBytes = rawValue;
        }
    }
}
