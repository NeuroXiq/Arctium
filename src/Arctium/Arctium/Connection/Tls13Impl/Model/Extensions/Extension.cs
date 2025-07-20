using Arctium.Standards.Connection.Tls13Impl.Model;

namespace Arctium.Standards.Connection.Tls13Impl.Model.Extensions
{
    abstract class Extension
    {
        public abstract ExtensionType ExtensionType { get; }

        public override string ToString()
        {
            return string.Format("ExtensionType: {0}; {1}", ExtensionType, base.ToString());
        }
    }
}
