using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Collections.Generic;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    class ExtensionBuilder
    {
        static Dictionary<HandshakeExtensionType, IExtensionBuilder> extTypeToBuilderMap;

        // for every extensions exist class which build object from raw bytes
        // this builder can be easy find using this dictionary holding [extension type (enum)] -> [extenions builder instance] key-value pair
        // note that all extensions inherit from IExtensionBuilder interface
        
        // to create new extesion builder:
        // 1. Add extension definition into /Protocol/HandshakeProtocol/Extensions/ namespace (folder path)
        //      note: Extension must inherit from 'HandshakeExtension' class located in folder above
        //
        // 2. Create builder class in Protocol/BinaryOps/Builder/HandshakeBuilder/ExtensionsBuilders (this current folder)
        //      note: builder class must inherit from IExtensionBuilder, builder build extension from extension data
        // 
        // 3. Add new extension builder instance to dictionary below with associated 'HandshakeExtensionType' key as you can see
        
        static ExtensionBuilder()
        {
            extTypeToBuilderMap = new Dictionary<HandshakeExtensionType, IExtensionBuilder>();

            extTypeToBuilderMap[HandshakeExtensionType.ApplicationLayerProtocolNegotiation] = new ALPNExtensionBuilder();
            extTypeToBuilderMap[HandshakeExtensionType.ServerName] = new ServerNameExtensionBuilder();
            extTypeToBuilderMap[HandshakeExtensionType.SignatureAlgorithms] = new SignatureAlgorithmsExtensionBuilder();
            
            //Elliptic curve cryptography 
            extTypeToBuilderMap[HandshakeExtensionType.EllipticCurves] = new EllipticCurvesExtensionBuilder();
            extTypeToBuilderMap[HandshakeExtensionType.EcPointFormats] = new ECPointFormatsExtensionBuilder();
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
            //ExtensionFormatData[] lists all extensions even if they cannot be translated to object.
            //ExtensionFormatData hold info about:
            // * buffer -> poiter to buffer where bytes are holded
            // * offset -> at which index DATA of the extension appear
            // * length -> length of the expected extension data 
            //        note: specific extensions builder gets extension data length and if this data length do not match while building 
            //              specific extension exception is throw
            //
            // * Type -> Extension type, used only to get specific extension builder from dictionary, ignored by builders.
            //
            // note_2: extensions builders do not get [ext_type][ext_data_length] (4 bytes) but only bytes after them (called 'extension data' in extension struct definition).
            //        this means that 'offset' points to 'extension data' not [ext_type].
            //        

            ExtensionFormatData[] extData = GetExtensionData(buffer, extensionsBlockOffset + 2, extensionDataLength);
            List<HandshakeExtension> extensionsObjects = new List<HandshakeExtension>();

            //build from bytes objects
            //unrecognized extensions are ignored.

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
