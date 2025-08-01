using Arctium.Protocol.Tls13Impl.Model;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
{
    internal class RecordSizeLimitExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.RecordSizeLimit;

        public ushort RecordSizeLimit { get; private set; }

        public RecordSizeLimitExtension(ushort recordSizeLimit)
        {
            RecordSizeLimit = recordSizeLimit;
        }
    }
}
