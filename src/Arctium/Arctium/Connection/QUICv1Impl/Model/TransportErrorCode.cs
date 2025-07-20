using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Standards.Connection.QUICv1Impl.Model
{
    /// <summary>
    /// RFC9000 20.1 Transport Error Codes
    /// </summary>
    internal enum TransportErrorCode: byte
    {
        /// <summary>
        /// An endpoint uses this with CONNECTION_CLOSE to signal that the
        /// connection is being closed abruptly in the absence of any error
        /// </summary>
        NoError = 0x00,

        /// <summary>
        /// The endpoint encountered an internal error and cannot continue
        /// with the connection.
        /// </summary>
        InternalError = 0x01,

        /// <summary>
        /// The server refused to accept a new connection
        /// </summary>
        ConnectionRefused = 0x02,

        /// <summary>
        /// An endpoint received more data than it permitted in its
        /// advertised data limits; see Section 4.
        /// </summary>
        FlowControlError = 0x03,

        /// <summary>
        /// An endpoint received a frame for a stream identifier that
        /// exceeded its advertised stream limit for the corresponding stream type
        /// </summary>
        StreamLimitError = 0x04,

        /// <summary>
        /// An endpoint received a frame for a stream that was not in a
        /// state that permitted that frame; see Section 3.
        /// </summary>
        StreamStateError = 0x05,

        /// <summary>
        /// (1) An endpoint received a STREAM frame containing data that
        /// exceeded the previously established final size, (2) an endpoint received a STREAM frame or a
        /// RESET_STREAM frame containing a final size that was lower than the size of stream data that
        /// was already received, or (3) an endpoint received a STREAM frame or a RESET_STREAM
        /// frame containing a different final size to the one already established.
        /// </summary>
        FinalSizeError = 0x06,

        /// <summary>
        /// An endpoint received a frame that was badly formatted --
        /// for instance, a frame of an unknown type or an ACK frame that has more acknowledgment
        /// ranges than the remainder of the packet could carry
        /// </summary>
        FrameEncodingError = 0x07,

        /// <summary>
        /// An endpoint received transport parameters that were
        /// badly formatted, included an invalid value, omitted a mandatory transport parameter,
        /// included a forbidden transport parameter, or were otherwise in error
        /// </summary>
        TransportParameterError = 0x08,

        /// <summary>
        ///The number of connection IDs provided by the peer
        /// exceeds the advertised active_connection_id_limit
        /// </summary>
        ConnectionIdLimitError = 0x09,

        /// <summary>
        /// An endpoint detected an error with protocol compliance that
        /// was not covered by more specific error codes
        /// </summary>
        ProtocolViolation = 0x0a,

        /// <summary>
        /// A server received a client Initial that contained an invalid Token field.
        /// </summary>
        InvalidToken = 0x0b,

        /// <summary>
        /// The application or application protocol caused the connection to
        /// be closed.
        /// </summary>
        ApplicationError = 0x0c,

        /// <summary>
        /// An endpoint has received more data in CRYPTO frames
        /// than it can buffer.
        /// </summary>
        CryptoBufferExceeded = 0x0d,

        /// <summary>
        /// An endpoint detected errors in performing key updates;
        /// </summary>
        KeyUpdateError = 0x0e,

        /// <summary>
        /// An endpoint has reached the confidentiality or integrity limit
        /// for the AEAD algorithm used by the given connection
        /// </summary>
        AEADLimitReached = 0x0f,

        /// <summary>
        /// An endpoint has determined that the network path is incapable of
        /// supporting QUIC. An endpoint is unlikely to receive a CONNECTION_CLOSE frame carrying
        /// this code except when the path does not support a large enough MTU
        /// </summary>
        NoViablePath = 0x10,

        // CryptoError = 0x0100,
    }
}
