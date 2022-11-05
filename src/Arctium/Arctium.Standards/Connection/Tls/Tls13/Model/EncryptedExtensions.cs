using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using System.Collections.Generic;

namespace Arctium.Standards.Connection.Tls.Tls13.Model
{
    internal class EncryptedExtensions
    {
        public List<Extension> Extensions { get; private set; }

        public EncryptedExtensions(Extension[] extensions)
        {
            Extensions = new List<Extension>(extensions);
        }
    }
}
