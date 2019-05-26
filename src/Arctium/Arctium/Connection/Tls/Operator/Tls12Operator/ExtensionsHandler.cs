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

        ///<summary>Convert TlsHandshakeExtension's on client side to <see cref="HandshakeExtension"/> object which can be injected to ClientHello message</summary>
        public HandshakeExtension[] BuildTlsHandshakeExtensionsOnClient(TlsHandshakeExtension[] tlsHandshakeExtensions)
        {
            List<HandshakeExtension> convertedToInternal = new List<HandshakeExtension>();

            // Conversion from public TlsHandshakeExtension object in client state to 
            // internal state-less HandshakeExtension. 'HandshakeExtension' objects can be directly formatter to bytes and 
            // sended to recipient.
            //
            // Current conversion is very simple and short. 

            foreach (TlsHandshakeExtension ext in tlsHandshakeExtensions)
            {
                HandshakeExtension internalExt = null;

                if (ext.internalExtensionType == HandshakeExtensionType.ApplicationLayerProtocolNegotiation)
                {
                    // get data from public extension
                    string[] supportedProtocolNames = ((AlpnExtension)ext).SupportedProtocolNames;

                    //convert to internal extension
                    internalExt = new ALPNExtension(supportedProtocolNames);
                    
                }
                else if (ext.internalExtensionType == HandshakeExtensionType.ServerName)
                {
                    string serverName = ((SniExtension)ext).ServerName;

                    //create internal extension
                    internalExt = new ServerNameExtension(serverName, NameType.HostName);

                }
                else throw new Exception("INTERNAL_ERROR_NOT_IMPLEMENTED::ExtensionsHandler, Unrecognized public api extension to format");

                convertedToInternal.Add(internalExt);
            }

            return convertedToInternal.ToArray();
        }

        public HandshakeExtension[] BuildClientHelloExtensions(TlsHandshakeExtension[] clientExtensions, TlsHandshakeExtension[] additionalClientExtensions)
        {
            throw new NotImplementedException();
        }
    }
}
