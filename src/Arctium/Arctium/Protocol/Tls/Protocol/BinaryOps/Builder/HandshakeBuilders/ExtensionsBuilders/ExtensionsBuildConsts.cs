﻿using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions.Enum;

namespace Arctium.Protocol.Tls.Protocol.BinaryOps.Builder.HandshakeBuilders.ExtensionsBuilders
{
    //TODO TLS12 Simplify this by assignment of this const value to the enum values
    static class ExtensionsBuildConsts
    {
        public static SignatureAlgorithmsExtension.SignatureAndHashAlgorithm GetSignatureHashAlgoPair(byte hashAlgoByte, byte signAlgoByte)
        {
            SignatureAlgorithm signAlgo = SignatureAlgorithm.NULL;
            HashAlgorithmType hashAlgo = HashAlgorithmType.NULL;

            switch (signAlgoByte)
            {
                case 1: signAlgo = SignatureAlgorithm.RSA; break;
                case 2: signAlgo = SignatureAlgorithm.DSA; break;
                case 3: signAlgo = SignatureAlgorithm.ECDSA; break;
            }

            switch (hashAlgoByte)
            {
                case 1: hashAlgo = HashAlgorithmType.MD5; break;
                case 2: hashAlgo = HashAlgorithmType.SHA1; break;
                case 3: hashAlgo = HashAlgorithmType.SHA224; break;
                case 4: hashAlgo = HashAlgorithmType.SHA256; break;
                case 5: hashAlgo = HashAlgorithmType.SHA384; break;
                case 6: hashAlgo = HashAlgorithmType.SHA512; break;
            }
            return new SignatureAlgorithmsExtension.SignatureAndHashAlgorithm(hashAlgo, signAlgo);
        }
    }
}
