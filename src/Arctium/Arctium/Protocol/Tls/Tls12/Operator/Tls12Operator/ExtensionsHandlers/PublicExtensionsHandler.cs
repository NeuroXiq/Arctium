using Arctium.Protocol.Tls.Tls12.Configuration.TlsExtensions;
using Arctium.Protocol.Tls.Exceptions;
using Arctium.Protocol.Tls.Protocol.AlertProtocol;
using Arctium.Protocol.Tls.Protocol.HandshakeProtocol.Extensions;
using System.Collections.Generic;
using Arctium.Protocol.Tls.Configuration.TlsExtensions;

namespace Arctium.Protocol.Tls.Tls12.Operator.Tls12Operator.ExtensionsHandlers
{
    class PublicExtensionsHandler
    {
        //
        // TlsHandshakeExtension class is a public defined extensions for public API usage (e.g. in configuration objects). 
        // This extensions are located in Connection/Tls/Configuration/TlsExtensions and must be translated to appriopriate 
        // HandshakeExtension (internal usage). This extensions include ALPN and SNI 
        //
        // 'HandshakeExtension' contains only fields necessary to format to bytes and transfer over record layer.

        public PublicExtensionsHandler() { }


        


        public TlsHandshakeExtension[] GetExtensionsResultFromServerHello(HandshakeExtension[] serverHelloExtension)
        {
            if (serverHelloExtension == null)
                return new TlsHandshakeExtension[0];

            List<TlsHandshakeExtension> results = new List<TlsHandshakeExtension>();
            foreach (var ext in serverHelloExtension)
            {
                switch (ext.Type)
                {
                    case HandshakeExtensionType.ApplicationLayerProtocolNegotiation:
                        results.Add(new AlpnExtension(((ALPNExtension)ext).ProtocolNameList[0]));
                        break;
                    default: break;
                }
            }

            return results.ToArray();
        }

        public HandshakeExtension[] ConvertPublicExtensionsToClientHelloRequest(TlsHandshakeExtension[] publicExtensions)
        {
            if (publicExtensions == null) return null;
            List<HandshakeExtension> converted = new List<HandshakeExtension>();
            foreach (var ext in publicExtensions)
            {
                switch (ext.internalExtensionType)
                {
                    case HandshakeExtensionType.ApplicationLayerProtocolNegotiation:
                        converted.Add(new ALPNExtension(((AlpnExtension)ext).SupportedProtocolNames));
                        break;
                    case HandshakeExtensionType.ServerName:
                        SniExtension sni = (SniExtension)ext;
                        converted.Add(new ServerNameExtension(sni.ServerName,NameType.HostName));
                        break;
                    default:break;
                }
            }

            return converted.ToArray();
        }

        internal HandshakeExtension TryBuildAlpnResponse(TlsHandshakeExtension[] configExtensions, HandshakeExtension[] extensionsFromClient)
        {
            if (configExtensions == null) return null;

            AlpnExtension publicExt = null;
            ALPNExtension chExt = null;

            foreach (var ext in configExtensions)
            {
                if (ext.internalExtensionType == HandshakeExtensionType.ApplicationLayerProtocolNegotiation)
                {
                    publicExt = (AlpnExtension)ext;
                    break;
                }
            }
            foreach (var clientExt in extensionsFromClient)
            {
                if (clientExt.Type == HandshakeExtensionType.ApplicationLayerProtocolNegotiation)
                {
                    chExt = (ALPNExtension)clientExt;
                    break;
                }
            }


            if (publicExt == null || chExt == null) return null;

            foreach (var supportedByServer in ((AlpnExtension)publicExt).SupportedProtocolNames)
            {
                foreach (var supportedByClient in ((ALPNExtension)chExt).ProtocolNameList)
                {
                    if (supportedByClient == supportedByServer) return new ALPNExtension(new string[] { supportedByServer });
                }
            }

            throw new FatalAlertException("Extensions Handler", "On trying to negotiate ALPN protocol", 
                (int)AlertDescription.NoApplicationProtocol, "Client and server do not share common application layer protocol name");
        }

        //public HandshakeExtension[] BuildAllHandshakeExtensionsOnServer(HandshakeExtension[] clientHelloExtensions, TlsHandshakeExtension[] toResponseExtensions)
        //{
        //    List<HandshakeExtension> allExtensions = new List<HandshakeExtension>();
        //    HandshakeExtension[] tlsHandshakeExtension = BuildResponseToExtensionsInClientHello(clientHelloExtensions, toResponseExtensions);

        //    allExtensions.AddRange(tlsHandshakeExtension);

        //    return allExtensions.ToArray();
        //}

        /////<summary>Build result for ClientHello extensions based on provided TlsHandshakeExtension's</summary>
        //private HandshakeExtension[] BuildResponseToExtensionsInClientHello(HandshakeExtension[] clientHelloExtensions, TlsHandshakeExtension[] tlsHandshakeExtensions)
        //{
        //    List<HandshakeExtension> responseExtensions = new List<HandshakeExtension>();

        //    foreach (var responseExt in tlsHandshakeExtensions)
        //    {
        //        foreach (var clientExt in clientHelloExtensions)
        //        {
        //            if (clientExt.Type == responseExt.internalExtensionType)
        //            {
        //                HandshakeExtension responseResult = null;

        //                switch (responseExt.internalExtensionType)
        //                {
        //                    case HandshakeExtensionType.ApplicationLayerProtocolNegotiation:
        //                        responseResult = ConvertToPublicExtensionResult(responseExt, clientExt);
        //                        break;
        //                    default: throw new Exception("INTERNAL::EXCEPTION Some problems with TlsHandshakeExtension processin in Extensions handler. Type do not match");
        //                }

        //            }
        //        }
        //    }

        //    return responseExtensions.ToArray();
        //}

        //private HandshakeExtension ConvertToPublicExtensionResult(TlsHandshakeExtension responseDataExt, HandshakeExtension clientRequestExtData)
        //{

        //}
        /////<summary>Tricky extensiosn not sure how should it works </summary>
        //public TlsHandshakeExtension[] GetExtensionsResultFromServerHello(ServerHello serverHello)
        //{
        //    HandshakeExtension[] extensions = serverHello.Extensions;

        //    foreach (var ext in extensions)
        //    {

        //    }
        //}

        //public HandshakeExtension[] BuildClientHelloExtensions(TlsHandshakeExtension[] additionalExtensions)
        //{
        //    if (additionalExtensions == null) return new HandshakeExtension[0];
        //    List<HandshakeExtension> convertedToInternal = new List<HandshakeExtension>();


        //    foreach (TlsHandshakeExtension ext in additionalExtensions)
        //    {
        //        HandshakeExtension internalExt = ConvertToInternalExtension(ext);

        //        convertedToInternal.Add(internalExt);
        //    }

        //    return convertedToInternal.ToArray();
        //}

        //private TlsHandshakeExtension ConvertToPublicExtension(HandshakeExtension ext)
        //{
        //    throw new NotImplementedException();

        //}

        //private HandshakeExtension ConvertToInternalExtension(TlsHandshakeExtension ext)
        //{
        //    switch (ext.internalExtensionType)
        //    {

        //    }
        //}
    }
}
