using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNS.Model
{
    public class Header
    {
        // header fields

        public ushort Id;
        public QRType QR;
        public Opcode Opcode;
        
        /// <summary>
        /// Authoritative Answer - this bit is valid in responses,
        /// and specifies that the responding name server is an
        /// authority for the domain name in question section.
        /// </summary>
        public bool AA;

        /// <summary>
        ///  TrunCation - specifies that this message was truncated
        /// due to length greater than that permitted on the
        /// transmission channel
        /// </summary>
        public bool TC;

        /// <summary>
        /// Recursion Desired - this bit may be set in a query and
        /// is copied into the response.If RD is set, it directs
        /// the name server to pursue the query recursively.
        /// Recursive query support is optional.
        /// </summary>
        public bool RD;

        /// <summary>
        /// Recursion Available - this be is set or cleared in a
        /// response, and denotes whether recursive query support is
        /// available in the name server
        /// </summary>
        public bool RA;

        public byte Z { get { return 0; } } // this is const

        /// <summary>
        /// Response code
        /// </summary>
        public ResponseCode RCode;

        /// <summary>
        /// number of entries in the question section
        /// </summary>
        public ushort QDCount;


        /// <summary>
        /// number of resource records in the answer section
        /// </summary>
        public ushort ANCount;

        /// <summary>
        /// number of name server resource records in the authority records section
        /// </summary>
        public ushort NSCount;

        /// <summary>
        /// number of resource records in the additional records section
        /// </summary>
        public ushort ARCount;
    }
}
