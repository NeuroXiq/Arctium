using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters.ExtensionsFormatters
{
    //
    // This class creates from 'HandshakeExtension' array binary list of TLS extensions.
    //
    // format of extensions list:
    // [total length of all '[extension]' (2 bytes) ][extension][extension][extension]....
    // [extension] == [extension type (2 bytes)][data length (2 bytes)][data bytes]
    //                               
    //
    // Im not sure how to format extensions when: 
    //  1. value is null (HandshakeExtension[] extensions == null)
    //  2. list is empty (extensions.Length == 0)
    //
    // Decided to treat this 2 cases in following manned:
    // 1. When value is null then do nothing (0 bytes writed)
    // 2. When extensions list length == 0 then add first 2 length bytes of value 0
    // 
    //  First case indicates that there is 'nothing', 
    //  second that there IS extensions list but is empty. 
    //
    // Considerations above can change in future updates.
    //

    public class ExtensionsFormatter
    {
        public ExtensionsFormatter() { }


        public int GetLength(HandshakeExtension[] extensions)
        {
            if (extensions == null) return 0;
            if (extensions.Length == 0) return 2;

            int totalLength = 2 + (4 * extensions.Length);

            foreach (HandshakeExtension ext in extensions)
            {
                switch (ext.Type)
                {
                    case HandshakeExtensionType.ServerName: totalLength += GetServerNameDataLength((ServerNameExtension)ext); break;
                    case HandshakeExtensionType.ApplicationLayerProtocolNegotiation: totalLength +=  GetALPNDataLength((ALPNExtension)ext); break;
                    default: continue;
                }
            }

            return totalLength;
        }

        private int GetALPNDataLength(ALPNExtension ext)
        {
            int totalStringsLength = 0;
            foreach (string protName in ext.ProtocolNameList) totalStringsLength += protName.Length;

            totalStringsLength += ext.ProtocolNameList.Length; // (1 bytes indicates each name length )

            return totalStringsLength;

        }

        private int GetServerNameDataLength(ServerNameExtension ext)
        {
            // 1 + 1 == hostName bytes + name length byte
            return 1 + 1 + ext.Name.Length;
        }

        public int FormatExtensions(byte[] buffer, int offset, HandshakeExtension[] extensions)
        {
            if (extensions == null) return 0;
            if (extensions.Length == 0) return 2;

        }
    }
}
