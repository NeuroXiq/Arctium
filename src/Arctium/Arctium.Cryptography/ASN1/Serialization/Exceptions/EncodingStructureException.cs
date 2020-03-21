using Arctium.Cryptography.ASN1.Exceptions;

namespace Arctium.Cryptography.ASN1.Serialization.Exceptions
{
    public class EncodingStructureException : Asn1Exception
    {
        public EncodingStructureException(byte[] buffer, long offset, string message) : base(message)
        {
        }
    }
}
