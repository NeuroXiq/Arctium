using System;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions;
using Arctium.Protocol.Tls.Protocol.BinarOps.HandshakeBuilders.ExtensionsBuilders;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    class SignatureAlgorithmsExtensionBuilder : IExtensionBuilder
    {
        public HandshakeExtension BuildExtension(ExtensionFormatData extData)
        {
            //validate length, 
            // signature and hash algo is a byte pair, first byte indicates hash, second sign.

            if (extData.Length % 2 != 0) throw new Exception("Invalid length of the signature algorithms extension");
            if (extData.Length == 0) throw new Exception("Not sure to throw this but something is wrong that in SignatureAlgorithms extension sign/hash pair is emtpy");

            int pairsCount = extData.Length / 2;
            SignatureAlgorithmsExtension.SignatureAndHashAlgorithm[] hashSignPairs = new SignatureAlgorithmsExtension.SignatureAndHashAlgorithm[pairsCount];

            int next = 0;

            for (int i = 0; i < extData.Length; i += 2)
            {
                hashSignPairs[next] = ExtensionsBuildConsts.GetSignatureHashAlgoPair(extData.Buffer[i + extData.DataOffset],extData.Buffer[i + 1 + extData.DataOffset]);
                next++;
            }

            return new SignatureAlgorithmsExtension(hashSignPairs);
        }
    }
}
