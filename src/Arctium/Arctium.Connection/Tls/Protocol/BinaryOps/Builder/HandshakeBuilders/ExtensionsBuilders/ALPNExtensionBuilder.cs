using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Text;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    class ALPNExtensionBuilder : IExtensionBuilder
    {
        public HandshakeExtension BuildExtension(ExtensionFormatData extFormatData)
        {
            if (extFormatData.Length < 2) throw new Exception("Invalid length of the ALPN extension");

            int protocolNameListLength = NumberConverter.ToUInt16(extFormatData.Buffer, extFormatData.DataOffset);
            if (protocolNameListLength != extFormatData.Length - 2) throw new Exception("Extension ALPN Invalid length of protocol_name_list");

            if (protocolNameListLength != extFormatData.Length - 2) throw new Exception("ALPN Invalid length");

            if (protocolNameListLength == 0)
            {
                return new ALPNExtension(new string[0]);
            }

            //2 == protocol_name_list length + 1 length byte of at least 1 protocol presented (protocolNameListLength is not 0)
            if (protocolNameListLength < 2 + 1) throw new Exception("ALPN invalid length");

            int lengthOffset = extFormatData.DataOffset + 2;
            int nameOffset = lengthOffset + 1;
            int nameLength = -1;
            int maxOffset = extFormatData.Length + extFormatData.DataOffset - 1;

            List<string> protocolNames = new List<string>();

            int toReadInList = protocolNameListLength;

            while (toReadInList > 0)
            {
                if (nameOffset > maxOffset || lengthOffset > maxOffset) throw new Exception("ALPN invlid length");
                nameLength = extFormatData.Buffer[lengthOffset];

                string protocolName = Encoding.ASCII.GetString(extFormatData.Buffer, nameOffset, nameLength);
                protocolNames.Add(protocolName);

                toReadInList -= 1 + nameLength;
                nameOffset += 1 + nameLength;
                lengthOffset += 1 + nameLength;
            }


            string[] allNames = protocolNames.ToArray();

            return new ALPNExtension(allNames);
        }
    }
}
