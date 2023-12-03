using Arctium.Standards.Connection.Tls13Impl.Model;

namespace Arctium.Standards.Connection.Tls13Impl.Model.Extensions
{
    /// <summary>
    /// Internal (only in Arctium implementation) special extension (not specified in any document)
    /// to store & serialize generate GREASE value. This is 'helper' class
    /// </summary>
    internal class GREASEInternalExtension : Extension
    {
        public override ExtensionType ExtensionType => (ExtensionType)ExtensionTypeGREASE;

        public ushort ExtensionTypeGREASE { get; private set; }
        public byte[] ExtensionContent { get; private set; }

        public GREASEInternalExtension(ushort extensionType, byte[] extensionContent)
        {
            ExtensionTypeGREASE = extensionType;
            ExtensionContent = extensionContent;
        }
    }
}
