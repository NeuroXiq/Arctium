using Arctium.Connection.Tls.Protocol.HandshakeProtocol.Extensions;
using System;

namespace Arctium.Connection.Tls.Configuration.TlsExtensions
{
    public class AlpnExtension : TlsHandshakeExtension
    {
        private string[] requestNames;
        private string responseName;

        ///<summary>Gets supported protocol names by client</summary>
        ///<exception cref="InvalidOperationException">If current instance is created as server response</exception>
        public string[] RequestNames
        {
            get
            {
                if (ConnectionEndType == ConnectionEnd.Server)
                    throw new InvalidOperationException("Cannot get RequetNames because AlpnExtension is created as client request");

                return requestNames;
            }
        }

        ///<summary>Gets selected by server protocol name</summary>
        ///<exception cref="InvalidOperationException">If current instance is created as a client request</exception>
        public string ResponseName
        {
            get
            {
                if (ConnectionEndType == ConnectionEnd.Client)
                    throw new InvalidOperationException("Cannot get ResponseName because AlpnExtension is created as server response");
                return responseName;
            }
        }

        private AlpnExtension(string[] requestNames) : base(HandshakeExtensionType.ApplicationLayerProtocolNegotiation, ConnectionEnd.Server)
        {
            this.requestNames = requestNames;
        }

        private AlpnExtension(string responseName) : base(HandshakeExtensionType.ApplicationLayerProtocolNegotiation, ConnectionEnd.Client)
        {
            this.responseName = responseName;
        }

        ///<summary>Creates client request of the ALPN extension</summary>
        ///<param name="names">Supported protocol names</param>
        public static AlpnExtension CreateRequest(string[] names)
        {
            return new AlpnExtension(names);
        }

        ///<summary>Creates server response for the ALPN extension</summary>
        ///<param name="name">Selected protocol name by server</param>
        public static AlpnExtension CreateResponse(string name)
        {
            return new AlpnExtension(name);
        }
    }
}
