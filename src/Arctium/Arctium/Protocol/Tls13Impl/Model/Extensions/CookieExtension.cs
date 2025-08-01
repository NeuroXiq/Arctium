using Arctium.Protocol.Tls13Impl.Model;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
{
    internal class CookieExtension : Extension
    {
        public byte[] Cookie { get; private set; }

        public override ExtensionType ExtensionType => ExtensionType.Cookie;

        public CookieExtension(byte[] cookie)
        {
            Cookie = cookie;
        }
    }
}
