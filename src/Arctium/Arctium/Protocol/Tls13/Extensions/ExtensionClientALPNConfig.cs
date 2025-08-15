using Arctium.Shared;
using Arctium.Protocol.Tls13Impl.Model.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Arctium.Protocol.Tls13.Extensions
{
    /// <summary>
    /// Application layer protocol negotiation extension configuration for client
    /// This class stores protocol names list that will be send to server in ALPN extension.
    /// Allows to specifiy raw byte values that are not defined in any specification as well as
    /// constant protocol names (like HTTP1, HTTP2/2 etc.) defined in current implementation.
    /// Must have at least single protocol name, if list is empty exception will be thrown.
    /// Must not add GREASE (RFC 8701) values
    /// </summary>
    public class ExtensionClientALPNConfig
    {
        internal List<byte[]> ProtocolList { get; private set; }

        /// <summary>
        /// Creates new instance with empty protocol list
        /// </summary>
        public ExtensionClientALPNConfig()
        {
            ProtocolList = new List<byte[]>();
        }

        /// <summary>
        /// helper to validate
        /// </summary>
        private void InternalAdd(byte[] value)
        {
            Validation.NotEmpty(value, "protocolname", "invalid protocol name, it must not be empty by specification");
            Validation.Argument(value.Length == 1 && value[0] == 0, "protocolname", "protocol name is just single zero-byte (means empty string that cannot be)");
            bool allzeros = true;
            for (int i = 0; i < value.Length; i++) allzeros &= value[i] == 0;

            Validation.Argument(allzeros, "protocolname", "protocol name constsis of all zero bytes, this is not valid or not supported now");

            byte[] grease = GREASE.CS_ALPN.FirstOrDefault(grease => MemOps.Memcmp(grease, value));

            if (grease != null)
            {
                string greaseString = BitConverter.ToString(grease);
                Validation.Argument(true, "protocolname", $"current value is GREASE extension and cannot be configure. Invalid value: {greaseString}");
            }

            // for safty to be immutable later
            var cloned = value.Clone() as byte[];
            ProtocolList.Add(cloned);
        }

        /// <summary>
        /// Adds protocol name to list as raw bytes (not standarized values are supported)
        /// Bytes cannot be all zeros and must not be null or empty
        /// </summary>
        /// <param name="protcolNameRawBytes">Protocol names as raw bytes (should be string UTF-8)</param>
        public void Add(byte[] protcolNameRawBytes)
        {
            InternalAdd(protcolNameRawBytes);
        }

        /// <summary>
        /// Adds protocol name to list. String is converted into bytes in UTF-8 formattion
        /// </summary>
        /// <param name="protocolName"></param>
        public void Add(string protocolName)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(protocolName);

            InternalAdd(bytes);
        }

        /// <summary>
        /// Adds protocol name to list.
        /// Protocol name as bytes  is standarized constant value.
        /// </summary>
        /// <param name="standarizedProtocolName"></param>
        public void Add(ALPNProtocol standarizedProtocolName)
        {
            byte[] bytes = ProtocolNameListExtension.GetConstantBytes((ProtocolNameListExtension.Protocol)standarizedProtocolName);

            InternalAdd(bytes);
        }
    }
}
