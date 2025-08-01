using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
{
    internal class QuicTransportParametersExtension : Extension
    {
        public static readonly TransportParameterId[] SerializationInfoValueIsInteger =
        {
            TransportParameterId.MaxIdleTimeout,
            TransportParameterId.MaxUdpPayloadSize,
            TransportParameterId.InitialMaxData,
            TransportParameterId.InitialMaxStreamDataBidiRemote,
            TransportParameterId.InitialMaxStreamDataBidiLocal,
            TransportParameterId.InitialMaxStreamDataUni,
            TransportParameterId.InitialMaxStreamsBidi,
            TransportParameterId.InitialMaxStreamsUni,
            TransportParameterId.AckDelayExponent,
            TransportParameterId.MaxAckDelay,
            TransportParameterId.ActiveConnectionIdLimit,
        };

        public static readonly TransportParameterId[] SerializationInfoValueIsByteArray =
        {
            TransportParameterId.InitialSourceConnectionId,
            TransportParameterId.OriginalDestinationConnectionId,
            TransportParameterId.StatelessResetToken,
            TransportParameterId.RetrySourceConnectionId,
        };



        public override ExtensionType ExtensionType => ExtensionType.QuicTransportParameters;

        public TransportParameter[] TransportParameters { get; private set; }

        public QuicTransportParametersExtension(TransportParameter[] parameters)
        {
            TransportParameters = parameters;
        }

        public enum TransportParameterId : ulong
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
            ActiveConnectionIdLimit = 0x0e,
            InitialSourceConnectionId = 0x0f,
            RetrySourceConnectionId = 0x10,

            /// <summary>
            /// special value in current Arctium implementation
            /// if unknown/not implemented yet
            /// </summary>
            UnknownNotImplemented = 0xFF
        }

        [DebuggerDisplay("Id = {System.Enum.GetName(typeof(Arctium.Protocol.Tls13Impl.Model.Extensions.QuicTransportParametersExtension.TransportParameterId), Id)}, Length = {Length}")]
        public class TransportParameter
        {
            public TransportParameterId Id { get; set; }
            public ulong Length { get; set; }
            // public object Value { get; set; }

            public TransportParameter(TransportParameterId id)
            {
                Id = id;
            }
        }

        public class OriginalDestinationConnectionId : ByteArrayTransportParameter
        {
            /// <summary>
            /// This parameter is the value of the Destination
            /// Connection ID field from the first Initial packet sent by the client; see Section 7.3. This
            /// transport parameter is only sent by a server.
            /// </summary>
            public OriginalDestinationConnectionId(byte[] value) : base(TransportParameterId.OriginalDestinationConnectionId, value)
            {

            }
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

        public class MaxIdleTimeout : IntegerTransportParameter
        {
            /// <summary>
            /// max idle in miliseconds. Zero if no idle
            /// </summary>
            public MaxIdleTimeout(ulong value) : base(TransportParameterId.MaxIdleTimeout, value)
            {
            }
        }

        public class StatelessResetToken : ByteArrayTransportParameter
        {
            /// <summary>
            /// Sequence of 16 bytes
            /// </summary>
            public StatelessResetToken(byte[] value) : base(TransportParameterId.StatelessResetToken, value)
            {
            }
        }

        public class MaxUdpPayloadSize : IntegerTransportParameter
        {
            /// <summary>
            /// Max UDP payload size in bytes, max is 65527 and lower than 1200 are invalid
            /// </summary>
            /// <param name="value"></param>
            public MaxUdpPayloadSize(ulong value) : base(TransportParameterId.MaxUdpPayloadSize, value)
            {
            }
        }

        public class InitialMaxData : IntegerTransportParameter
        {
            public InitialMaxData(ulong value) : base(TransportParameterId.InitialMaxData, value)
            {
            }
        }

        public class InitialMaxStreamDataBidiLocal : IntegerTransportParameter
        {
            public InitialMaxStreamDataBidiLocal(ulong value) : base(TransportParameterId.InitialMaxStreamDataBidiLocal, value)
            {
            }
        }

        public class InitialMaxStreamDataBidiRemote : IntegerTransportParameter
        {
            public InitialMaxStreamDataBidiRemote(ulong value) : base(TransportParameterId.InitialMaxStreamDataBidiRemote, value)
            {
            }
        }

        public class InitialMaxStreamDataUni : IntegerTransportParameter
        {
            public InitialMaxStreamDataUni(ulong value) : base(TransportParameterId.InitialMaxStreamDataUni, value)
            {
            }
        }

        public class InitialMaxStreamsBidi : IntegerTransportParameter
        {
            public InitialMaxStreamsBidi(ulong value) : base(TransportParameterId.InitialMaxStreamsBidi, value)
            {
            }
        }

        public class InitialMaxStreamsUni : IntegerTransportParameter
        {
            public InitialMaxStreamsUni(ulong value) : base(TransportParameterId.InitialMaxStreamsUni, value)
            {
            }
        }

        public class AckDelayExponent : IntegerTransportParameter
        {
            public AckDelayExponent(ulong value) : base(TransportParameterId.AckDelayExponent, value)
            {
            }
        }

        public class MaxAckDelay : IntegerTransportParameter
        {
            public MaxAckDelay(ulong value) : base(TransportParameterId.MaxAckDelay, value)
            {
            }
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

        public class InitialSourceConnectionId : ByteArrayTransportParameter
        {
            public InitialSourceConnectionId(byte[] value) : base(TransportParameterId.InitialSourceConnectionId, value)
            {
            }
        }

        public class RetrySourceConnectionId
        {

        }

    }
}
