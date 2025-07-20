using Arctium.Shared.Helpers;
using System.Collections.Generic;
using Arctium.Cryptography.Utils;
using System.Linq;
using System;
using Arctium.Standards.X509.X509Cert;
using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls13.Extensions;
using Arctium.Standards.Connection.Tls13.Messages;
using Arctium.Standards.Connection.Tls13Impl.Model;
using Arctium.Standards.Connection.Tls13Impl.Model.Extensions;

namespace Arctium.Standards.Connection.Tls13
{
    internal class Tls13ServerProtocolInstanceContext
    {
        public Tls13ServerConfig Config { get; private set; }
        public ReadOnlyMemory<byte> InstanceId { get; internal set; }

        public Tls13ServerProtocolInstanceContext(byte[] instanceUniqueId, Tls13ServerConfig config)
        {
            InstanceId = instanceUniqueId;
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


        /*
         * Extension handling wrappers
         */

        internal void ExtensionHandleALPN(ProtocolNameListExtension alpnExtension, out bool ignore, out AlertDescription? alertFatal, out int? selectedIndex)
        {
            if (Config.ExtensionALPN != null)
            {
                // clone for safety (not modified after calling selector, maybe in selector malicious code affect array)
                // remove grease
                byte[][] protNamesClone = alpnExtension.ProtocolNamesList
                    .Where(prot => !GREASE.CS_ALPN.Any(grease => MemOps.Memcmp(grease, prot)))
                    .Select(originalProtocol => (byte[])originalProtocol.Clone())
                    .ToArray();

                var result = Config.ExtensionALPN.Handle(protNamesClone);

                if (result.ActionType == ExtensionServerConfigALPN.ResultType.Success)
                {
                    Validation.NumberInRange(result.SelectedIndex, 0, protNamesClone.Length - 1, nameof(result.SelectedIndex), "index out of range of possible protocol list");
                    selectedIndex = -1;

                    // find result in original list (before removing grease)
                    for (int i = 0; i < alpnExtension.ProtocolNamesList.Count; i++)
                    {
                        if (MemOps.Memcmp(protNamesClone[result.SelectedIndex], alpnExtension.ProtocolNamesList[i]))
                        {
                            selectedIndex = i;
                            break;
                        }
                    }

                    Validation.ThrowInternal(selectedIndex == -1);

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
            var clientCerts = certificate.CertificateList.Select(c => (byte[])c.CertificateEntryRawBytes.Clone()).ToArray();

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

        internal ServerConfigHandshakeClientAuthentication.Action PostHandshakeClientCertificate(Certificate postHandshakeClientCert)
        {
            var clientCerts = postHandshakeClientCert.CertificateList.Select(c => (byte[])c.CertificateEntryRawBytes.Clone()).ToArray();

            return Config.PostHandshakeClientAuthentication.CertificateFromClientReceived(clientCerts, new List<APIModel.Extension>());
        }

        internal void Event_PostHandshakeClientAuthenticationSuccess(Certificate certMsg)
        {
            Validation.ThrowInternal(Config.PostHandshakeClientAuthentication == null);

            var certs = certMsg.CertificateList.Select(c => (byte[])c.CertificateEntryRawBytes.Clone()).ToArray();

            Config.PostHandshakeClientAuthentication.OnClientAuthSuccess(certs, InstanceId);
        }

        internal CertificateAuthoritiesExtension GetExtension_CertificateAuthorities()
        {
            if (Config.ExtensionCertificateAuthorities == null) return null;

            return new CertificateAuthoritiesExtension(Config.ExtensionCertificateAuthorities.Authorities);
        }
    }
}
