﻿using Arctium.Shared;
using Arctium.Shared;
using Arctium.Protocol.Tls13.Messages;
using Arctium.Protocol.Tls13Impl.Model;
using Arctium.Protocol.Tls13Impl.Model.Extensions;
using System;

namespace Arctium.Protocol.Tls13
{
    public class Tls13ClientContext
    {
        public Tls13ClientConfig Config { get; private set; }

        public Tls13ClientContext(Tls13ClientConfig config)
        {
            config.ThrowIfInvalidState();
            Config = config;
        }

        public void ThrowIfInvalidState()
        {
            Config.ThrowIfInvalidState();
        }

        public static Tls13ClientContext DefaultUnsafe()
        {
            var config = Tls13ClientConfig.DefaultUnsafe();
            return new Tls13ClientContext(config);
        }

        internal void SaveTicket(byte[] ticket,
            byte[] nonce,
            byte[] resumptionMasterSecret,
            uint lifetime,
            uint ticketAgeAdd,
            HashFunctionId hashFunctionId)
        {
            var pskTicketStore = Config.PreSharedKey?.ClientStore;

            if (pskTicketStore == null) return;

            pskTicketStore.Save(new PskTicket(ticket, nonce, resumptionMasterSecret, lifetime, ticketAgeAdd, hashFunctionId));
        }

        internal PskTicket[] GetPskTickets()
        {
            var pskTicketStore = Config.PreSharedKey?.ClientStore;

            return pskTicketStore.GetToSendInClientHello();
        }

        internal ClientConfigHandshakeClientAuthentication.Certificates HandshakeClientAuthenticationGetCertificate(CertificateRequest handshakeCertificateRequest)
        {
            if (Config.HandshakeClientAuthentication == null) return null;

            var certs = Config.HandshakeClientAuthentication.GetCertificateToSendToServer(APIModel.APIModelMapper.MapExtensions(handshakeCertificateRequest.Extensions));

            return certs;
        }

        internal ClientConfigHandshakeClientAuthentication.Certificates PostHandshakeClientAuthenticationGetCertificate(CertificateRequest certRequest)
        {
            if (Config.PostHandshakeClientAuthentication == null) Validation.ThrowInternal();

            var certs = Config.PostHandshakeClientAuthentication.GetCertificateToSendToServer(APIModel.APIModelMapper.MapExtensions(certRequest.Extensions));

            return certs;
        }

        internal CertificateAuthoritiesExtension GetExtension_CertificateAuthorities()
        {
            if (Config.ExtensionCertificateAuthorities == null) return null;

            return new CertificateAuthoritiesExtension(Config.ExtensionCertificateAuthorities.Authorities);
        }

        internal SupportedGroupExtension GetExtension_SupportedGroups()
        {
            return new SupportedGroupExtension(Config.ExtensionSupportedGroups.InternalNamedGroups);
        }
    }
}
