using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Text;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    class ServerNameExtensionBuilder : IExtensionBuilder
    {
        public HandshakeExtension BuildExtension(ExtensionFormatData extData)
        {
            //
            // rfc says that this list  must not contain more than one  
            // server name of the one type. Currently is defined only one NameType (host_name, see rfc 6066) which means that there 
            // must be only one server name.
            // I'm assume that this will not change and ignore possible future updates of the Nametype enumeration.


            int maxOffset = extData.DataOffset + extData.Length - 1;

            // 2 + 2 + 1 == server_name_list_length(2 bytes) + name_type(1 byte) + host_name_length(2 bytes)
            if (extData.Length < 2 + 2 + 1) throw new Exception("ServerName invalid length");

            int serverNameListLength = NumberConverter.ToUInt16(extData.Buffer, extData.DataOffset);
            NameType nameType = (NameType)extData.Buffer[extData.DataOffset + 2];
            int serverNameLength = NumberConverter.ToUInt16(extData.Buffer, extData.DataOffset + 3);

            if (serverNameLength != serverNameListLength - 3) throw new Exception("ServerName extension building: Invalid or not implemented (server length)");

            string name = Encoding.ASCII.GetString(extData.Buffer, extData.DataOffset + 2 + 2 + 1, extData.Length - 5);


            ServerNameExtension sName = new ServerNameExtension(name, NameType.HostName);

            return sName;
        }
    }
}
