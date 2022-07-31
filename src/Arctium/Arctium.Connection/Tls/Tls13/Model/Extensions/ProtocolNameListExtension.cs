using System.Linq;
using System.Text;

namespace Arctium.Connection.Tls.Tls13.Model.Extensions
{
    class ProtocolNameListExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.ApplicationLayerProtocolNegotiation;

        public byte[][] ProtocolNamesList { get; private set; }
        public string[] ProtocolNameListString { get; private set; }

        public ProtocolNameListExtension(byte[][] protocolNameList)
        {
            ProtocolNamesList = protocolNameList;
            ProtocolNameListString = protocolNameList.Select(bytes => Encoding.ASCII.GetString(bytes)).ToArray();
        }
    }
}
