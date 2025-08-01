using Arctium.Shared.Helpers.Buffers;
using Arctium.Shared.Other;
using Arctium.Protocol.Tls13.Extensions;
using Arctium.Protocol.Tls13Impl.Model;
using Arctium.Protocol.Tls13Impl.Model.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Arctium.Protocol.Tls13Impl.Protocol.Helpers
{
    /// <summary>
    /// Injecting GREASE values to server/client messagse
    /// Simple algo: select random values and inject into message.
    /// </summary>
    internal static class GreaseInject
    {
        static readonly Random random = new Random();
        static readonly object _lock = new object();

        static int Random(int maxNotIncluded)
        {
            lock (_lock)
            {
                return random.Next(maxNotIncluded);
            }
        }

        static ushort[] Random(ushort[] array, int count)
        {
            if (count == 0) return new ushort[0];

            List<ushort> values = new List<ushort>();
            int start = Random(array.Length);
            int greaseMaxCount = array.Length;

            for (int i = 0; i < count && i < greaseMaxCount; i++)
            {
                values.Add(array[(start + i) % greaseMaxCount]);
            }

            return values.ToArray();
        }

        static byte[][] Random(byte[][] array, int count)
        {
            List<byte[]> values = new List<byte[]>();
            int start = Random(array.Length);
            int greaseMaxCount = array.Length;

            for (int i = 0; i < count && i < greaseMaxCount; i++)
            {
                values.Add(array[(start + i) % greaseMaxCount]);
            }

            return values.ToArray();
        }


        static List<GREASEInternalExtension> RandomExtensions(int count)
        {
            var content = new byte[Random(32)];
            int start = Random(count);
            List<GREASEInternalExtension> values = new List<GREASEInternalExtension>();
            int greaseMaxCount = GREASE.EX_NG_SA_VER.Length;

            for (int i = 0; i < count && i < greaseMaxCount; i++)
            {
                var type = GREASE.EX_NG_SA_VER[(start + i) % greaseMaxCount];

                values.Add(new GREASEInternalExtension(type, content));
            }

            return values;
        }

        public static void ClientHello(ClientHello message, ExtensionClientConfigGREASE config)
        {
            if (config == null) return;

            var msgType = message.GetType();

            var ch = message as ClientHello;

            var randomCS = Random(GREASE.CS_ALPN, config.CipherSuitesCount).Select(c => (CipherSuite)MemMap.ToUShort2BytesBE(c, 0));
            ch.CipherSuites.AddRange(randomCS);

            ch.Extensions.AddRange(RandomExtensions(config.ExtensionsCount));

            var supportedGroups = ch.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.SupportedGroups) as SupportedGroupExtension;

            if (supportedGroups != null)
            {
                var groups = Random(GREASE.EX_NG_SA_VER, config.SupportedGroupsCount).Select(g => (SupportedGroupExtension.NamedGroup)g);
                supportedGroups.NamedGroupList.AddRange(groups);
            }

            var keyShares = ch.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.KeyShare) as KeyShareClientHelloExtension;

            if (keyShares != null)
            {
                var sharesGrease = Random(GREASE.EX_NG_SA_VER, config.KeyShareCount);
                // min length of group is 1 (so must be rand(32) + 1)
                var shares = sharesGrease.Select(s => new KeyShareEntry((SupportedGroupExtension.NamedGroup)s, new byte[Random(32) + 1])).ToArray();

                keyShares.ClientShares.AddRange(shares);
            }

            var sigAlgos = ch.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.SignatureAlgorithms) as SignatureSchemeListExtension;

            if (sigAlgos != null)
            {
                var sigs = Random(GREASE.EX_NG_SA_VER, config.SignatureAlgorithmsCount);
                sigAlgos.Schemes.AddRange(sigs.Select(s => (SignatureSchemeListExtension.SignatureScheme)s));
            }

            var sigalgocert = ch.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.SignatureAlgorithmsCert) as SignatureSchemeListExtension;

            if (sigalgocert != null)
            {
                var sigscert = Random(GREASE.EX_NG_SA_VER, config.SignatureAlgorithmsCount);
                sigalgocert.Schemes.AddRange(sigscert.Select(s => (SignatureSchemeListExtension.SignatureScheme)s));
            }

            var versions = ch.Extensions.First(e => e.ExtensionType == ExtensionType.SupportedVersions) as ClientSupportedVersionsExtension;

            if (versions != null)
            {
                var gvers = Random(GREASE.EX_NG_SA_VER, config.SupportedVersionsCount);
                versions.Versions.AddRange(gvers);
            }

            var pskke = ch.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.PskKeyExchangeModes) as PreSharedKeyExchangeModeExtension;

            if (pskke != null)
            {
                var gke = Random(GREASE.PSK_KE_MODES, config.PskKeModesCount);
                pskke.KeModes.AddRange(gke.Select(k => (PreSharedKeyExchangeModeExtension.PskKeyExchangeMode)k));
            }

            var alpn = ch.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.ApplicationLayerProtocolNegotiation) as ProtocolNameListExtension;

            if (alpn != null)
            {
                var galpn = Random(GREASE.CS_ALPN, config.ALPNCount);
                alpn.ProtocolNamesList.AddRange(galpn);
            }
        }

        public static void ForServer(object msg, ExtensionServerConfigGREASE config)
        {
            if (config == null) return;

            else if (msg is CertificateRequest) Server(msg as CertificateRequest, config);
            else if (msg is NewSessionTicket) Server(msg as NewSessionTicket, config);
            else Validation.ThrowInternal();
        }

        private static void Server(CertificateRequest cr, ExtensionServerConfigGREASE config)
        {
            cr.Extensions.AddRange(RandomExtensions(config.CertificateRequestExtensionsCount));

            var sigalgos = cr.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.SignatureAlgorithms) as SignatureSchemeListExtension;
            var sigalgocert = cr.Extensions.FirstOrDefault(e => e.ExtensionType == ExtensionType.SignatureAlgorithmsCert) as SignatureSchemeListExtension;

            if (sigalgocert != null)
            {
                var gsigalgo = Random(GREASE.EX_NG_SA_VER, config.CertificateRequestSignatureAlgorithmsCount);
                sigalgocert.Schemes.AddRange(gsigalgo.Select(s => (SignatureSchemeListExtension.SignatureScheme)s));
            }

            if (sigalgocert != null)
            {
                var gsigalgocert = Random(GREASE.EX_NG_SA_VER, config.CertificateRequestSignatureAlgorithmsCertCount);
            }
        }

        private static void Server(NewSessionTicket nst, ExtensionServerConfigGREASE config)
        {
            nst.Extensions.AddRange(RandomExtensions(config.NewSessionTicketExtensionsCount));
        }
    }
}
