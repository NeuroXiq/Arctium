using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Model
{
    public class Header
    {
        // header fields

        public ushort Id;
        public QRType QR;
        public Opcode Opcode;
        public bool AA;
        public bool TC;
        public bool RD;
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
