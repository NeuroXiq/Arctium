using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Collections.Generic;
using Arctium.Connection.Tls.Protocol.BinarOps.HandshakeBuilders.ExtensionsBuilders;
using System.Text;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    class ExtensionBuilder
    {
        static Dictionary<HandshakeExtensionType, IExtensionBuilder> extTypeToBuilderMap;

        static ExtensionBuilder()
        {
            extTypeToBuilderMap = new Dictionary<HandshakeExtensionType, IExtensionBuilder>();

            extTypeToBuilderMap[HandshakeExtensionType.ApplicationLayerProtocolNegotiation] = new ALPNExtensionBuilder();
            extTypeToBuilderMap[HandshakeExtensionType.ServerName] = new ServerNameExtensionBuilder();
            extTypeToBuilderMap[HandshakeExtensionType.SignatureAlgorithms] = new SignatureAlgorithmsExtensionBuilder();
        }

        public ExtensionBuilder()
        {

        }

        public HandshakeExtension[] GetExtensions(byte[] buffer, int extensionsBlockOffset, int extensionsBlockLength)
        {
            if (extensionsBlockLength == 0) return null;

            if (extensionsBlockLength < 2)
                throw new Exception("extensions block length must be at least 2 bytes (length bytes)");

            int extensionDataLength = NumberConverter.ToUInt16(buffer, extensionsBlockOffset);
            if (extensionDataLength != extensionsBlockLength - 2) throw new Exception("Invalid length of extensions");

            //get informations about extensions in raw data buffer
            //ExtData[] lists all extensions even if they cannot be translated to object.
            ExtensionFormatData[] extData = GetExtensionData(buffer, extensionsBlockOffset + 2, extensionDataLength);
            List<HandshakeExtension> extensionsObjects = new List<HandshakeExtension>();

            //build from bytes objects
            //unrecognized extensions are ignored.
            //to parse new extension, add in switch its type and create object which inherits from HandshakeExtension

            for (int i = 0; i < extData.Length; i++)
            {
                HandshakeExtension readyExtension = BuildExtension(extData[i], buffer);
                //ignore all unregognized extensions type (null)
                if(readyExtension != null)
                    extensionsObjects.Add(readyExtension);
            }

            return extensionsObjects.ToArray();
        }

        //if extensions is unrecognized (no builder presen now) returns null
        private HandshakeExtension BuildExtension(ExtensionFormatData extData, byte[] buffer)
        {
            if (extTypeToBuilderMap.ContainsKey(extData.Type))
            {
                IExtensionBuilder builderFromType = extTypeToBuilderMap[extData.Type];

                HandshakeExtension buildedExtensions = builderFromType.BuildExtension(extData);

                return buildedExtensions;
            }
            else return null;
        }

        private ExtensionFormatData[] GetExtensionData(byte[] buffer, int firstExtensionOffset, int allExtsLength)
        {
            int maxOffset = allExtsLength + firstExtensionOffset - 1;
            int toBuildBytes = allExtsLength;
            int curExtOffset = firstExtensionOffset;

            List<ExtensionFormatData> extsData = new List<ExtensionFormatData>();

            while (toBuildBytes > 0)
            {
                // 2 + 2 == extension_type + extension_data_length
                if (curExtOffset + 2 + 2 - 1 > maxOffset) throw new Exception("invalid extension ");

                ExtensionFormatData curExt = new ExtensionFormatData();
                curExt.Type = (HandshakeExtensionType)NumberConverter.ToUInt16(buffer, curExtOffset);
                curExt.Length = NumberConverter.ToUInt16(buffer, curExtOffset + 2);
                curExt.DataOffset = curExtOffset + 4;
                curExt.Buffer = buffer;

                
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
