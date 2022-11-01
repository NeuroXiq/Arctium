using Arctium.Standards.Connection.Tls.Tls13.API;
using Arctium.Standards.Connection.Tls.Tls13.Model;
using Arctium.Standards.Connection.Tls.Tls13.Model.Extensions;
using Arctium.Shared.Helpers;
using System.Collections.Generic;
using Arctium.Cryptography.Utils;
using System.Linq;
using System;
using Arctium.Standards.X509.X509Cert;
using Arctium.Standards.Connection.Tls.Tls13.API.Extensions;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Standards.Connection.Tls.Tls13.API.Messages;
using Arctium.Shared.Other;

namespace Arctium.Standards.Connection.Tls.Tls13.API
{
    public class Tls13ServerContext
    {
        public Tls13ServerConfig Config { get; private set; }

        public Tls13ServerContext(Tls13ServerConfig config)
        {
            config.ThrowIfInvalidObjectState();
            Config = config;
        }

        internal PskTicket GetPskTicket(PreSharedKeyClientHelloExtension preSharedKeyExtension,
            HashFunctionId selectedCipherSuiteHashFunctionId,
            out int clientSelectedIndex)
        {
            var pskTicketStore = Config.PreSharedKey.ServerStore;

            clientSelectedIndex = -1;
            var clientIdentities = preSharedKeyExtension.Identities;

            var tickets = preSharedKeyExtension.Identities.Select(identity => identity.Identity).ToArray();

            var selectedTicket = pskTicketStore.GetTicket(tickets, selectedCipherSuiteHashFunctionId);

            if (selectedTicket == null) return null;

            for (int i = 0; clientSelectedIndex == -1 && i < preSharedKeyExtension.Identities.Length; i++)
            {
                if (MemOps.Memcmp(clientIdentities[i].Identity, selectedTicket.Ticket))
                {
                    clientSelectedIndex = i;
                }
            }

            return selectedTicket;
        }

        public void SavePskTicket(byte[] resumptionMasterSecret,
            byte[] ticket,
            byte[] nonce,
            uint ticketLifetime,
            uint ticketAgeAdd,
            HashFunctionId hashFunctionId)
        {
            var pskTicketStore = Config.PreSharedKey.ServerStore;

            pskTicketStore.SaveTicket(new PskTicket(ticket, nonce, resumptionMasterSecret, ticketLifetime, ticketAgeAdd, hashFunctionId));
        }

        public static Tls13ServerContext Default(X509CertWithKey[] certificates)
        {
            var config = Tls13ServerConfig.Default(certificates);
            var context = new Tls13ServerContext(config);

            return context;
        }


        /*
         * Extension handling wrappers
         */

        internal void ExtensionHandleALPN(ProtocolNameListExtension alpnExtension, out bool ignore, out AlertDescription? alertFatal, out int? selectedIndex)
        {
            if (Config.ExtensionALPN != null)
            {
                // clone for safety (not modified after calling selector, maybe in selector malicious code affect array)
                byte[][] protNamesClone = alpnExtension.ProtocolNamesList
                    .Select(originalProtocol => (byte[])originalProtocol.Clone())
                    .ToArray();

                var result = Config.ExtensionALPN.Handle(protNamesClone, new ExtensionServerConfigALPN.ResultSelect(protNamesClone.Length));

                if (result.ActionType == ExtensionServerConfigALPN.ResultType.Success)
                {
                    selectedIndex = result.SelectedIndex;
                    alertFatal = null;
                    ignore = false;
                }
                else if (result.ActionType == ExtensionServerConfigALPN.ResultType.NotSelectedIgnore)
                {
                    ignore = true;
                    selectedIndex = -1;
                    alertFatal = null;
                }
                else
                {
                    ignore = false;
                    selectedIndex = -1;
                    alertFatal = AlertDescription.NoApplicationProtocol;
                }

                return;
            }

            selectedIndex = -1;
            ignore = true;
            alertFatal = null;
        }

        internal ExtensionServerConfigServerName.ResultAction HandleExtensionServerName(ServerNameListClientHelloExtension serverNameExt)
        {
            if (Config.ExtensionServerName == null)
                return ExtensionServerConfigServerName.ResultAction.Success;
            
            var hostName = (byte[])serverNameExt.ServerNameList[0].HostName.Clone();
            
            return Config.ExtensionServerName.Handle(hostName);
        }

        internal ServerConfigHandshakeClientAuthentication.Action ClientCertificate(Certificate certificate)
        {
            var clientCerts = certificate.CertificateList.Select(c => ((byte[])c.CertificateEntryRawBytes.Clone())).ToArray();

            return Config.HandshakeClientAuthentication.CertificateFromClientReceived(clientCerts, new List<APIModel.Extension>());
        }

        internal OidFiltersExtension OidFiltersExtension()
        {
            if (Config.ExtensionServerConfigOidFilters == null) return null;

            var filters = Config.ExtensionServerConfigOidFilters.Filters
                    .Select(f => new OidFiltersExtension.OidFilter(f.CertificateExtensionOid, f.CertificateExtensionValues))
                    .ToArray();

            return new OidFiltersExtension(filters);
        }

        internal ServerConfigPostHandshakeClientAuthentication.Action PostHandshakeClientCertificate(Certificate postHandshakeClientCert)
        {
            var clientCerts = postHandshakeClientCert.CertificateList.Select(c => ((byte[])c.CertificateEntryRawBytes.Clone())).ToArray();

            return Config.PostHandshakeClientAuthentication.CertificateFromClientReceived(clientCerts, new List<APIModel.Extension>());
        }

        internal void Event_PostHandshakeClientAuthenticationSuccess(Certificate certMsg)
        {
            Validation.ThrowInternal(Config.PostHandshakeClientAuthentication == null);

            var certs = certMsg.CertificateList.Select(c => (byte[])c.CertificateEntryRawBytes.Clone()).ToArray();

            Config.PostHandshakeClientAuthentication.OnClientAuthSuccess(certs);
        }

        internal CertificateAuthoritiesExtension GetExtension_CertificateAuthorities()
        {
            if (Config.ExtensionCertificateAuthorities == null) return null;

            return new CertificateAuthoritiesExtension(Config.ExtensionCertificateAuthorities.Authorities);
        }
    }
}
