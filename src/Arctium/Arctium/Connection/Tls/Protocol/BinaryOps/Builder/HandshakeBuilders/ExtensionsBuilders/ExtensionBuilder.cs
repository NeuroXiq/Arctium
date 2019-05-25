using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Collections.Generic;
using Arctium.Connection.Tls.Protocol.BinarOps.HandshakeBuilders.ExtensionsBuilders;
using System.Text;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    class ExtensionBuilder
    {
        //
        // Extensions specific constant values
        //
         
        

        

        //auxiliary struct contains informations about extensions.
        struct ExtData
        {
            public int DataOffset;
            public int Length;
            public HandshakeExtensionType Type;
        }

        public HandshakeExtension[] GetExtensions(byte[] buffer, int extensionsBlockOffset, int extensionsBlockLength)
        {
            if (extensionsBlockLength < 2)
                throw new Exception("extensions block length must be at least 2 bytes (length bytes)");

            int extensionDataLength = NumberConverter.ToUInt16(buffer, extensionsBlockOffset);
            if (extensionDataLength != extensionsBlockLength - 2) throw new Exception("Invalid length of extensions");

            //get informations about extensions in raw data buffer
            //ExtData[] lists all extensions even if they cannot be translated to object.
            ExtData[] extData = GetExtensionData(buffer, extensionsBlockOffset + 2, extensionDataLength);
            List<HandshakeExtension> extensionsObjects = new List<HandshakeExtension>();

            //build from bytes objects
            //unrecognized extensions are ignored.
            //to parse new extension, add in switch its type and create object which inherits from HandshakeExtension

            for (int i = 0; i < extData.Length; i++)
            {
                HandshakeExtension readyExtension = BuildExtension(extData[i], buffer);
                if(readyExtension != null)
                    extensionsObjects.Add(readyExtension);
            }

            return extensionsObjects.ToArray();
        }

        private HandshakeExtension BuildExtension(ExtData extData, byte[] buffer)
        {
            switch (extData.Type)
            {
                case HandshakeExtensionType.ApplicationLayerProtocolNegotiation: return BuildALPN(extData, buffer);
                case HandshakeExtensionType.SignatureAlgorithms: return BuildSignatureAlgorithms(extData, buffer);
                case HandshakeExtensionType.ServerName: return BuildServerName(extData, buffer);
                //case HandshakeExtensionType.MaxFragmentLength: return BuildMaxFragmentLength(extData, buffer);

                default:  return null;
            }
        }

        private HandshakeExtension BuildMaxFragmentLength(ExtData extData, byte[] buffer)
        {
            throw new NotImplementedException();
        }

        private HandshakeExtension BuildServerName(ExtData extData, byte[] buffer)
        {
            //
            // rfc says that this list  must not contain more than one  
            // server name of the one type. Currently is defined only one NameType (host_name, see rfc 6066) which means that there 
            // must be only one server name.
            // I'm assume that this will not change and ignore possible future updates of the Nametype enumeration.


            int maxOffset = extData.DataOffset + extData.Length - 1;

            // 2 + 2 + 1 == server_name_list_length(2 bytes) + name_type(1 byte) + host_name_length(2 bytes)
            if (extData.Length < 2 + 2 + 1) throw new Exception("ServerName invalid length");

            int serverNameListLength = NumberConverter.ToUInt16(buffer, extData.DataOffset);
            NameType nameType = (NameType)buffer[extData.DataOffset + 2];
            int serverNameLength = NumberConverter.ToUInt16(buffer, extData.DataOffset + 3);

            if (serverNameLength != serverNameListLength - 3) throw new Exception("ServerName extension building: Invalid or not implemented (server length)");

            string name = Encoding.ASCII.GetString(buffer, extData.DataOffset + 2 + 2 + 1, extData.Length - 5);


            ServerNameExtension sName = new ServerNameExtension(name);

            return sName;
        }

        private SignatureAlgorithmsExtension BuildSignatureAlgorithms(ExtData extData, byte[] buffer)
        {
            //validate length, 
            // signature and hash algo is a byte pair, first byte indicates hash, second sign.

            if (extData.Length % 2 != 0) throw new Exception("Invalid length of the signature algorithms extension");
            if (extData.Length == 0) throw new Exception("Not sure to throw this but something is wrong that in SignatureAlgorithms extension sign/hash pair is emtpy");

            int pairsCount = extData.Length / 2;
            SignatureAlgorithmsExtension.SignatureAndHashAlgorithm[] hashSignPairs = new SignatureAlgorithmsExtension.SignatureAndHashAlgorithm[pairsCount];

            int next = 0;

            for (int i = 0; i < extData.Length; i+=2)
            {
                hashSignPairs[next] = ExtensionsBuildConsts.GetSignatureHashAlgoPair(buffer[i + extData.DataOffset], buffer[i + 1 + extData.DataOffset]);
                next++;
            }

            return new SignatureAlgorithmsExtension(hashSignPairs);
        }

        private HandshakeExtension BuildALPN(ExtData extData, byte[] buffer)
        {
            if (extData.Length < 2) throw new Exception("Invalid length of the ALPN extension");

            int protocolNameListLength = NumberConverter.ToUInt16(buffer, extData.DataOffset);
            if (protocolNameListLength != extData.Length - 2) throw new Exception("Extension ALPN Invalid length of protocol_name_list");

            if (protocolNameListLength != extData.Length - 2) throw new Exception("ALPN Invalid length");

            if (protocolNameListLength == 0)
            {
                return new ALPNExtension(new string[0]);
            }

            //2 == protocol_name_list length + 1 length byte of at least 1 protocol presented (protocolNameListLength is not 0)
            if (protocolNameListLength < 2 + 1) throw new Exception("ALPN invalid length");

            int lengthOffset = extData.DataOffset + 2;
            int nameOffset = lengthOffset + 1;
            int nameLength = -1;
            int maxOffset = extData.Length + extData.DataOffset - 1;

            List<string> protocolNames = new List<string>();

            int toReadInList = protocolNameListLength;

            while (toReadInList > 0)
            {
                if (nameOffset > maxOffset || lengthOffset > maxOffset) throw new Exception("ALPN invlid length");
                nameLength = buffer[lengthOffset];

                string protocolName = Encoding.ASCII.GetString(buffer, nameOffset, nameLength);
                protocolNames.Add(protocolName);

                toReadInList -= 1 + nameLength;
                nameOffset += 1 + nameLength;
                lengthOffset += 1 + nameLength;
            }


            string[] allNames = protocolNames.ToArray();

            return new ALPNExtension(allNames);
        }

        private ExtData[] GetExtensionData(byte[] buffer, int firstExtensionOffset, int allExtsLength)
        {
            int maxOffset = allExtsLength + firstExtensionOffset - 1;
            int toBuildBytes = allExtsLength;
            int curExtOffset = firstExtensionOffset;

            List<ExtData> extsData = new List<ExtData>();

            while (toBuildBytes > 0)
            {
                // 2 + 2 == extension_type + extension_data_length
                if (curExtOffset + 2 + 2 - 1 > maxOffset) throw new Exception("invalid extension ");

                ExtData curExt = new ExtData();
                curExt.Type = (HandshakeExtensionType)NumberConverter.ToUInt16(buffer, curExtOffset);
                curExt.Length = NumberConverter.ToUInt16(buffer, curExtOffset + 2);
                curExt.DataOffset = curExtOffset + 4;

                
                extsData.Add(curExt);
                //shift to next extension
                toBuildBytes -= 2 + 2 + curExt.Length;
                curExtOffset += 2 + 2 + curExt.Length;
            }

            if (toBuildBytes != 0) throw new Exception("something is wrong with this extensions");

            return extsData.ToArray();
        }
    }
}
