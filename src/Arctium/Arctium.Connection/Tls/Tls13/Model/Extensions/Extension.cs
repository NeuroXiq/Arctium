namespace Arctium.Connection.Tls.Tls13.Model.Extensions
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
