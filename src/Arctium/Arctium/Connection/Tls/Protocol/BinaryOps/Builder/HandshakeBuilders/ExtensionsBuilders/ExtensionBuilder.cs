using System;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    class ExtensionBuilder
    {
        //
        // Extensions specific constant values
        //
         
        

        


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
            //ExtData[] lists all extensions even if they cannot translated to object.
            ExtData[] extData = GetExtensionData(buffer, extensionsBlockOffset + 2, extensionDataLength);
            List<HandshakeExtension> extensionsObjects = new List<HandshakeExtension>();

            //build from ExtData objects
            //unrecognized extensions are ignored.
            //to parse new extension, add in switch its type and create object inherited from HandshakeExtension

            for (int i = 0; i < extData.Length; i++)
            {
                HandshakeExtension readyExtension = BuildExtension(extData[i]);
                if(readyExtension != null)
                    extensionsObjects.Add(readyExtension);
            }

            return extensionsObjects.ToArray();
        }

        private HandshakeExtension BuildExtension(ExtData extData)
        {
            switch (extData.Type)
            {
                case HandshakeExtensionType.ApplicationLayerProtocolNegotiation: return BuildALPN(extData);
                case HandshakeExtensionType.SignatureAlgorithms: return BuildSignatureAlgorithms(extData);

                default:  return null;
            }
        }

        private HandshakeExtension BuildSignatureAlgorithms(ExtData extData)
        {
            
        }

        private HandshakeExtension BuildALPN(ExtData extData)
        {
            throw new NotImplementedException();
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
