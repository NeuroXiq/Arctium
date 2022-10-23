namespace Arctium.Standards.Connection.Tls.Tls13.Model.Extensions
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
