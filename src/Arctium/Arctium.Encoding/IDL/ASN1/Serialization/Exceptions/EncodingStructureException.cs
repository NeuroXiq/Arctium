using Arctium.Encoding.IDL.ASN1.Exceptions;

namespace Arctium.Encoding.IDL.ASN1.Serialization.Exceptions
{
    public class EncodingStructureException : Asn1Exception
    {
        public EncodingStructureException(byte[] buffer, long offset, string message) : base(message)
        {
        }
    }
}
