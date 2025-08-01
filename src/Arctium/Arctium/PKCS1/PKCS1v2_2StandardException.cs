using Arctium.Shared;

namespace Arctium.Standards.PKCS1
{
    public class PKCS1v2_2StandardException : StandardException
    {
        public PKCS1v2_2StandardException(string message) : base("PKCS#1 v2.2 (RFC 8017)", message) { }
    }
}
