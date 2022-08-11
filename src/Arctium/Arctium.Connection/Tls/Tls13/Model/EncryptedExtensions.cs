using Arctium.Connection.Tls.Tls13.Model.Extensions;

namespace Arctium.Connection.Tls.Tls13.Model
{
    internal class EncryptedExtensions
    {
        public Extension[] Extensions { get; private set; }

        public EncryptedExtensions(Extension[] extensions)
        {
            Extensions = extensions;
        }
    }
}
