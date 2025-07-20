using Arctium.Standards.Connection.Tls.Protocol.AlertProtocol;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.Formatter
{
    class AlertFormatter
    {
        public static byte[] FormatAlert(AlertDescription description, AlertLevel level)
        {
            byte[] alert = new byte[2];
            alert[0] = (byte)level;
            alert[1] = (byte)description;

            return alert;
        }
    }
}
