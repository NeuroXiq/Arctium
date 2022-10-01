using System;
using System.Diagnostics;

namespace Arctium.Standards.Connection.Tls.Tls13.Model.Extensions
{
    class UnknowExtension : Extension
    {
        private ExtensionType type;
        public override ExtensionType ExtensionType => type;

        public UnknowExtension(ExtensionType type)
        {
            this.type = type;
        }
    }
}
