using System;
using System.Diagnostics;
using Arctium.Standards.Connection.Tls13Impl.Model;

namespace Arctium.Standards.Connection.Tls13Impl.Model.Extensions
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
