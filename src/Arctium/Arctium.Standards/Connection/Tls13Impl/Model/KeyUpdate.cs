namespace Arctium.Standards.Connection.Tls13Impl.Model
{
    internal class KeyUpdate
    {
        public enum KeyUpdateRequest : byte
        {
            NotRequested = 0,
            UpdateRequested = 1
        }

        public KeyUpdateRequest RequestUpdate { get; private set; }

        public KeyUpdate(KeyUpdateRequest requestUpdate)
        {
            RequestUpdate = requestUpdate;
        }
    }
}
