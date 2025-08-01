﻿using System.Collections.Generic;
using Arctium.Protocol.Tls13Impl.Model;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
{
    class SupportedGroupExtension : Extension
    {
        public enum NamedGroup : ushort
        {
            /* Elliptic Curve Groups (ECDHE) */
            Secp256r1 = 0x0017,
            Secp384r1 = 0x0018,
            Secp521r1 = 0x0019,
            X25519 = 0x001D,
            Xx448 = 0x001E,

            /* Finite Field Groups (DHE) */
            Ffdhe2048 = 0x0100,
            Ffdhe3072 = 0x0101,
            Ffdhe4096 = 0x0102,
            Ffdhe6144 = 0x0103,
            Ffdhe8192 = 0x0104,

            /* Reserved Code Points */
            FfdhePrivateUse = 0x01FC /* 0x01FC..0x01FF */,
            EcdhePrivateUse = 0xFE00 /* 0xFE00..0xFEFF */,
        }

        public override ExtensionType ExtensionType => ExtensionType.SupportedGroups;

        public List<NamedGroup> NamedGroupList { get; private set; }

        public SupportedGroupExtension(NamedGroup[] namedGroups)
        {
            NamedGroupList = new List<NamedGroup>(namedGroups);
        }
    }
}
