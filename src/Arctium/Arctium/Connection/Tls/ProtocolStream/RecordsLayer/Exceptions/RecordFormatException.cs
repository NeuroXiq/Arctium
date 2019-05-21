using Arctium.Connection.Tls.Protocol.AlertProtocol;

namespace Arctium.Connection.Tls.ProtocolStream.RecordsLayer.Exceptions
{
    class RecordFormatException : RecordLayerAlertException
    {
        public RecordFormatException(AlertDescription alertDescription, string message) : base(alertDescription, message)
        {
        }
    }
}
