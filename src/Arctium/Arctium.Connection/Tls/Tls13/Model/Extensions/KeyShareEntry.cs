﻿namespace Arctium.Connection.Tls.Tls13.Model.Extensions
{
    internal class KeyShareEntry
    {
        public class UncompressedPointRepresentation
        {
            public byte LegacyForm { get; private set; }
            public byte[] X { get; private set; }
            public byte[] Y { get; private set; }

            public UncompressedPointRepresentation(byte legacyForm, byte[] x, byte[] y)
            {
                LegacyForm = legacyForm;
                X = x;
                Y = y;
            }
        }

        public SupportedGroupExtension.NamedGroup NamedGroup { get; private set; }
        public byte[] KeyExchangeRawBytes { get; private set; }
        public UncompressedPointRepresentation Representation { get; private set; }

        public KeyShareEntry(SupportedGroupExtension.NamedGroup namedGroup, UncompressedPointRepresentation representation)
        {
            Representation = representation;
        }


        public KeyShareEntry(SupportedGroupExtension.NamedGroup namedGroup, byte[] keyExchangeRawBytes)
        {
            NamedGroup = namedGroup;
            KeyExchangeRawBytes = keyExchangeRawBytes;
        }
    }
}
