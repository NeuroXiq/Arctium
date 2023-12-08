using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.Tls13Impl.Model.Extensions
{
    internal class QuicTransportParametersExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.QuicTransportParameters;

        public TransportParameter[] TransportParameters { get; private set; }

        public QuicTransportParametersExtension(TransportParameter[] parameters)
        {
            TransportParameters = parameters;
        }

        public enum TransportParameterId
        {
            OriginalDestinationConnectionId = 0x00,
            MaxIdleTimeout = 0x01,
            StatelessResetToken = 0x02,
            MaxUdpPayloadSize = 0x03,
            InitialMaxData = 0x04,
            InitialMaxStreamDataBidiLocal = 0x05,
            InitialMaxStreamDataBidiRemote = 0x06,
            InitialMaxStreamDataUni = 0x07,
            InitialMaxStreamsBidi = 0x08,
            InitialMaxStreamsUni = 0x09,
            AckDelayExponent = 0x0a,
            MaxAckDelay = 0x0b,
            DisableActiveMigration = 0x0c,
            PreferredAddress = 0x0d,
            ActiveConnectionIdLimit = 0x0,
            InitialSourceConnectionId = 0x0f,
            RetrySourceConnectionId = 0x10,

            /// <summary>
            /// special value in current Arctium implementation
            /// if unknown/not implemented yet
            /// </summary>
            UnknownNotImplemented = 0xFF
        }

        [DebuggerDisplay("Id = {System.Enum.GetName(typeof(Arctium.Standards.Connection.Tls13Impl.Model.Extensions.QuicTransportParametersExtension.TransportParameterId), Id)}, Length = {Length}")]
        public class TransportParameter
        {
            public TransportParameterId Id { get; set; }
            public ulong Length { get; set; }
            public object Value { get; set; }

            public TransportParameter(TransportParameterId id)
            {
                Id = id;
            }
        }

        public class OriginalDestinationConnectionId 
        {
            /// <summary>
            /// This parameter is the value of the Destination
            /// Connection ID field from the first Initial packet sent by the client; see Section 7.3. This
            /// transport parameter is only sent by a server.
            /// </summary>
            public byte[] Value;
        }

        /// <summary>
        /// Lots of parameters are just integer values,
        /// so create base class for them to simplify implementation
        /// </summary>
        public class IntegerTransportParameter : TransportParameter
        {
            public ulong Value;

            public IntegerTransportParameter(TransportParameterId id, ulong value) : base(id)
            {
                Value = value;
            }
        }

        public class ByteArrayTransportParameter : TransportParameter
        {
            public byte[] Value;

            public ByteArrayTransportParameter(TransportParameterId id, byte[] value) : base(id)
            {
                Value = value;
            }
        }

        public class UnknownTransportParameter : TransportParameter
        {
            // unknown does not have valid 'Id' field in 'TransportParameter' class
            // use this as temporary until not implemented
            public ulong TransportParameterId { get; set; }

            public UnknownTransportParameter(ulong id) : base(QuicTransportParametersExtension.TransportParameterId.UnknownNotImplemented)
            {
                TransportParameterId = id;
            }
        }

        public class MaxIdleTimeout 
        {
            public ulong Value;
        }

        public class StatelessResetToken 
        {
            /// <summary>
            /// Sequence of 16 bytes
            /// </summary>
            public byte[] Value;
        }

        //public class MaxUdpPayloadSize : IntegerTransportParameter
        //{
        //}

        public class InitialMaxData 
        {

        }

        public class InitialMaxStreamDataBidiLocal 
        {
        
        }

        public class InitialMaxStreamDataBidiRemote 
        {
        
        }

        public class InitialMaxStreamDataUni 
        {
        
        }

        public class InitialMaxStreamsBidi 
        {
        
        }

        public class InitialMaxStreamsUni 
        {
        
        }

        public class AckDelayExponent 
        {
        
        }

        public class MaxAckDelay 
        {
        
        }

        public class DisableActiveMigration 
        {
        
        }

        public class PreferredAddress : TransportParameter
        {
            public uint IPv4Address;
            public ushort IPv4Port;
            public byte[] IPv6Address;
            public ushort IPv6Port;
            public byte ConnectionIdLength;
            public byte[] ConnectionId;
            public byte[] StatelessResetToken;

            public PreferredAddress() : base(TransportParameterId.PreferredAddress)
            {
            }
        }

        public class ActiveConnectionIdLimit 
        {
        
        }

        public class InitialSourceConnectionId 
        {
        
        }

        public class RetrySourceConnectionId 
        {
        
        }

    }
}
