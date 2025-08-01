using Arctium.Protocol.Tls.Protocol.AlertProtocol.Enum;

namespace Arctium.Protocol.Tls.Protocol.AlertProtocol
{
    class Alert
    {
        public AlertLevel Level;
        public AlertDescription Description;

        public Alert(AlertLevel level, AlertDescription description)
        {
            Description = description;
            Level = level;
        }
    }
}
