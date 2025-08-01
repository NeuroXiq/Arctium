using System;
using System.Diagnostics;
using Arctium.Protocol.Tls13Impl.Model;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
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
