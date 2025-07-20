using Arctium.Standards.Connection.Tls13Impl.Model;

namespace Arctium.Standards.Connection.Tls13Impl.Model.Extensions
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
