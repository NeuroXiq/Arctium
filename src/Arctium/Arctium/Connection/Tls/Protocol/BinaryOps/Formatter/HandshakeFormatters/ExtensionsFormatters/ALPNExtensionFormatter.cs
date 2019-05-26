using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Text;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Formatter.HandshakeFormatters.ExtensionsFormatters
{
    class ALPNExtensionFormatter : ExtensionFormatterBase
    {
        public override int GetBytes(byte[] buffer, int offset, HandshakeExtension extension)
        {
            ALPNExtension alpnExtension = (ALPNExtension)extension;

            int listLength = 0;

            int insertNameOffset = offset + 3;
            int insertNameLengthOffset = insertNameOffset - 1;

            foreach (string protName in alpnExtension.ProtocolNameList)
            {
                buffer[insertNameLengthOffset] = (byte)protName.Length;
                int writedCount = Encoding.ASCII.GetBytes(protName, 0, protName.Length, buffer, insertNameOffset);

                listLength += writedCount + 1; //1 byte of length 
                insertNameOffset += writedCount + 1;
                insertNameLengthOffset += writedCount + 1;
            }

            return listLength;
        }

        public override int GetLength(HandshakeExtension extension)
        {
            throw new NotImplementedException();
        }
    }
}
