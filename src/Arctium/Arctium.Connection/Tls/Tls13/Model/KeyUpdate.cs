namespace Arctium.Connection.Tls.Tls13.Model
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
