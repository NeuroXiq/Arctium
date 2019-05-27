using Arctium.Connection.Tls.Configuration.TlsExtensions;
using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System;
using System.Collections.Generic;

namespace Arctium.Connection.Tls.Operator.Tls12Operator
{
    public class ExtensionsHandler
    {
        //
        // TlsHandshakeExtension class is a public defined extensions for public API usage (e.g. in configuration objects). 
        // This extensions are located in Connection/Tls/Configuration/TlsExtensions and must be translated to appriopriate 
        // HandshakeExtension (internal usage). This extensions include ALPN and SNI 
        //
        // HandshakeExtension contains only fields necessary to format to bytes and transfer.

        public ExtensionsHandler() { }


        public HandshakeExtension[] BuildAllHandshakeExtensionsOnServer(HandshakeExtension[] clientHelloExtensions, TlsHandshakeExtension[] toResponseExtensions)
        {
            List<HandshakeExtension> allExtensions = new List<HandshakeExtension>();
            
            HandshakeExtension[] tlsHandshakeExtension = BuildResponseToExtensions(clientHelloExtensions, toResponseExtensions);
            HandshakeExtension[] internalExtensions = GetInternalServerExtensions(clientHelloExtensions);

            allExtensions.AddRange(tlsHandshakeExtension);
            allExtensions.AddRange(internalExtensions);

            return allExtensions.ToArray();
        }

        ///<summary>Build result for ClientHello extensions based on provided TlsHandshakeExtension's</summary>
        private HandshakeExtension[] BuildResponseToExtensions(HandshakeExtension[] clientHelloExtensions, TlsHandshakeExtension[] tlsHandshakeExtensions)
        {
            

            List<HandshakeExtension> responseExtensions = new List<HandshakeExtension>();

            foreach (var responseExt in tlsHandshakeExtensions)
            {
                foreach (var clientExt in clientHelloExtensions)
                {
                    if (clientExt.Type == responseExt.internalExtensionType)
                    {
                        HandshakeExtension responseResult = responseExt.GetResponse(clientExt);
                        responseExtensions.Add(responseResult);
                    }
                }
            }

            return responseExtensions.ToArray();
        }

        ///<summary>Build server internal extensions to internal usage (should not be exposed as public, e.g. record max length)</summary>
        public HandshakeExtension[] GetInternalServerExtensions(HandshakeExtension[] serverHelloExtensions)
        {
            return new HandshakeExtension[0];
        }

        ///<summary>Build client internal extensions to internal usage (should not be exposed as public, e.g. record max length)</summary>
        public HandshakeExtension[] GetInternalClientExtensions()
        {
            return new HandshakeExtension[0];
        }

        public HandshakeExtension[] BuildClientHelloExtensions(TlsHandshakeExtension[] additionalExtensions)
        {
            HandshakeExtension[] extensions = BuildAdditionalClientExtensions(additionalExtensions);

            return extensions;
        }

        private HandshakeExtension[] BuildAdditionalClientExtensions(TlsHandshakeExtension[] additionalExtensions)
        {
            if (additionalExtensions == null) return new HandshakeExtension[0];
            List<HandshakeExtension> convertedToInternal = new List<HandshakeExtension>();

           
            foreach (TlsHandshakeExtension ext in additionalExtensions)
            {
                HandshakeExtension internalExt = ext.ConvertToClientRequest();
                convertedToInternal.Add(internalExt);
            }

            return convertedToInternal.ToArray();
        }
    }
}
