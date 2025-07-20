using System;
using Arctium.Standards.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Text;

namespace Arctium.Standards.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters.ExtensionsFormatters
{
    class ServerNameExtensionFormatter : ExtensionFormatterBase
    {
        public override int GetBytes(byte[] buffer, int offset, HandshakeExtension extension)
        {
            ServerNameExtension ext = (ServerNameExtension)extension;

            if (ext.Name == null)
            {
                //NumberConverter.FormatUInt16(0, buffer, offset);
                return 0;
            }

            //Assumes that there is only 1 entry in list

            //1 == name_type byte
            //2 == name_length bytes

            int listLength = (1 + 2 + ext.Name.Length);

            //2 bytes of list length
            NumberConverter.FormatUInt16((ushort)listLength, buffer, offset);

            buffer[offset + 2] = (byte)ext.NameType;
            NumberConverter.FormatUInt16((ushort)ext.Name.Length, buffer, offset + 3);

            Encoding.ASCII.GetBytes(ext.Name, 0, ext.Name.Length, buffer, offset + 5);

            //2 == 2 bytes of list length (list length is in 'ext_data')
            return listLength + 2;
        }

        public override int GetLength(HandshakeExtension extension)
        {
            ServerNameExtension ext = (ServerNameExtension)extension;

            if (ext.Name == null) return 0;
            else
            {
                //2 == length of server_name_list
                //2 == length of host_name vector
                //1 == name_type


                return 2 + 1 + 2 + (ext.Name.Length);
            }

        }
    }
}
