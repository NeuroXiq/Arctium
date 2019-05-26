using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Text;
using System.Collections.Generic;

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
    

    public class ExtensionsFormatter
    {
        static readonly Dictionary<HandshakeExtensionType, ExtensionFormatterBase> typeToFormatterMap;

        static ExtensionsFormatter()
        {
            typeToFormatterMap = new Dictionary<HandshakeExtensionType, ExtensionFormatterBase>();
        }
        


        public int GetLength(HandshakeExtension[] extensions)
        {
            if (extensions == null) return 0;
            if (extensions.Length == 0) return 0;

            //4 == extension_type (2 bytes) + ext_data_length (2 bytes) 
            //4 * extensions.Length == 4 * for each extension
            int totalLength = 2 + (4 * extensions.Length);

            foreach (HandshakeExtension ext in extensions)
            {
               
            }

            //now add ext_data_length + ext_type (4 byte)

            return totalLength;
        }

        private int GetALPNDataLength(ALPNExtension ext)
        {
            //format:
            //
            // 
            //

            int totalStringsLength = 0;
            foreach (string protName in ext.ProtocolNameList) totalStringsLength += protName.Length;

            totalStringsLength += ext.ProtocolNameList.Length; // (1 bytes indicates each name length )

            //2 byte of list length
            return totalStringsLength + 2;
        }

        private int GetServerNameDataLength(ServerNameExtension ext)
        {
            

            if (ext.Name == null) return 0;
            else
            {
                //2 == length of server_name_list
                //2 == length of host_name vector
                //1 == name_type


                return 2 + 1 + 2 + (ext.Name.Length);
            }

        }

        public int GetBytes(byte[] buffer, int offset, HandshakeExtension[] extensions)
        {
            if (extensions == null) return 0;
            if (extensions.Length == 0) return 0;

            // 2 + 2 == first extension type (2 bytes) + first extensions length ( 2 bytes )
            int extDataOffset = offset + 2 + 2;
            int totalLength = 0;

            foreach (HandshakeExtension ext in extensions)
            {
                

                //format ext_type (4 byte before ext_data)
                NumberConverter.FormatUInt16((ushort)ext.Type, buffer, extDataOffset - 4);

                //format ext_data_length (2 bytes before ext_data)
                NumberConverter.FormatUInt16((ushort)ext.Type, buffer, extDataOffset - 2);

                //move to next format offset
                totalLength += currentExtDataLength + 4;
                extDataOffset += currentExtDataLength + 4;
            }

            return totalLength;
        }
    }
}
