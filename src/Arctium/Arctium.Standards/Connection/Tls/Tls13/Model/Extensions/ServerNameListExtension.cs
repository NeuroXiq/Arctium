using System.Text;

namespace Arctium.Standards.Connection.Tls.Tls13.Model.Extensions
{
    internal class ServerNameListExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.ServerName;

        public enum NameTypeEnum : byte
        {
            HostName
        }

        public ServerName[] ServerNameList { get; private set; }

        public ServerNameListExtension(ServerName[] serverNameList)
        {
            ServerNameList = serverNameList;
        }

        public class ServerName
        {
            public NameTypeEnum NameType { get; private set; }
            public byte[] HostName { get; private set; }
            public string HostNameString { get; private set; }

            public ServerName(NameTypeEnum nameType, byte[] hostName)
            {
                NameType = nameType;
                HostName = hostName;
                HostNameString = Encoding.ASCII.GetString(hostName);
            }
        }
    }
}
