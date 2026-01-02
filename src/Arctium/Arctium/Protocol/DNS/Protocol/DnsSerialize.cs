using Arctium.Protocol.DNS.Model;
using Arctium.Shared;
using System.Diagnostics;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;

namespace Arctium.Protocol.DNS.Protocol
{
    public class DnsSerialize
    {
        public DnsSerialize()
        { }

        // encoding

        public void Encode(Message message, ByteBuffer buffer, bool isTcp = false)
        {
            int tcpLengthOffset = -1;
            
            if (isTcp)
            {
                tcpLengthOffset = buffer.AllocEnd(2);
            }

            Header h = message.Header;

            int start = buffer.AllocEnd(12);
            MemMap.ToBytes1UShortBE(h.Id, buffer.Buffer, start + 0);

            buffer[start + 2] =(byte)(
                (byte)h.QR << 7 |
                (byte)h.Opcode << 6 |
                (h.AA ? 1 : 0) << 2 |
                (h.TC ? 1 : 0) << 1 |
                (h.RD ? 1 : 0) << 0);

            buffer[start + 3] = (byte)
                (
                    h.Z << 4 |
                    (byte)h.RCode << 0 | 0
                );

            MemMap.ToBytes1UShortBE(h.QDCount, buffer.Buffer, start + 4);
            MemMap.ToBytes1UShortBE(h.ANCount, buffer.Buffer, start + 6);
            MemMap.ToBytes1UShortBE(h.NSCount, buffer.Buffer, start + 8);
            MemMap.ToBytes1UShortBE(h.ARCount, buffer.Buffer, start + 10);

            for (int i = 0; i < message.Question?.Length; i++)
            {
                Encode_Question(message.Question[i], buffer);
            }

            for (int i = 0; i < message.Answer?.Length; i++)
            {
                Encode_ResourceRecord(message.Answer[i], buffer);
            }

            for (int i = 0; i < message.Authority?.Length; i++)
            {
                Encode_ResourceRecord(message.Authority[i], buffer);
            }

            for (int i = 0; i < message.Additional?.Length; i++)
            {
                Encode_ResourceRecord(message.Additional[i], buffer);
            }

            if (isTcp)
            {
                int contentLength = buffer.Length - 2 - tcpLengthOffset;

                if (contentLength > ushort.MaxValue)
                {
                    throw new DnsException(DnsProtocolError.Internal, "serialized message length > ushort.maxvalue");
                }

                MemMap.ToBytes1UShortBE((ushort)contentLength, buffer.Buffer, tcpLengthOffset);
            }
            else if (buffer.Length - start > DnsConsts.UdpSizeLimit)
            {
                throw new DnsException(DnsProtocolError.Internal, "encoded > udp max length");
            }
        }

        private void Encode_ResourceRecord(ResourceRecord rr, ByteBuffer buffer)
        {
            buffer.Append((byte)rr.Name.Length);
            foreach (var c in rr.Name) buffer.Append((byte)c);
            buffer.Append(0);

            int i = buffer.AllocEnd(10);
            int rdLengthOffset = i + 8;
            MemMap.ToBytes1UShortBE((ushort)rr.Type, buffer.Buffer, i);
            MemMap.ToBytes1UShortBE((ushort)rr.Class, buffer.Buffer, i + 2);
            MemMap.ToBytes1IntBE((ushort)rr.TTL, buffer.Buffer, i + 4);

            switch (rr.Type)
            {
                case QType.A: Encode_RDataA((RDataA)rr.RData, buffer); break;
                case QType.NS: Encode_RDataNS((RDataNS)rr.RData, buffer); break;
                case QType.MD: Encode_RDataMD((RDataMD)rr.RData, buffer); break;
                case QType.MF: Encode_RDataMF((RDataMF)rr.RData, buffer); break;
                case QType.CNAME: Encode_RDataCNAME((RDataCNAME)rr.RData, buffer); break;
                case QType.SOA: Encode_RDataSOA((RDataSOA)rr.RData, buffer); break;
                case QType.MB: EncodeDomainName(buffer, ((RDataMB)rr.RData).MADName); break;
                case QType.MG: EncodeDomainName(buffer, ((RDataMG)rr.RData).MGMName); break;
                case QType.MR: EncodeDomainName(buffer, ((RDataMR)rr.RData).NewName); break;
                case QType.NULL: Encode_RDataNULL((RDataNULL)rr.RData, buffer); break;
                case QType.WKS: Encode_RDataWKS((RDataWKS)rr.RData, buffer); break;
                case QType.PTR: EncodeDomainName(buffer, ((RDataPTR)rr.RData).PtrDName); break;
                case QType.HINFO: Encode_RDataHINFO((RDataHINFO)rr.RData, buffer); break;
                case QType.MINFO: Encode_RDataMINFO((RDataMINFO)rr.RData, buffer); break;
                case QType.MX: Encode_RDataMX((RDataMX)rr.RData, buffer); break;
                case QType.TXT: Encode_RDataTXT((RDataTXT)rr.RData, buffer); break;
                case QType.AAAA: Encode_RDataAAAA((RDataAAAA)rr.RData, buffer); break;
                case QType.AXFR:
                case QType.MAILB:
                case QType.MAILA:
                case QType.All:
                    throw new NotImplementedException("Cannot encode this because this QType is only for queries");
                default: throw new DnsException(DnsProtocolError.EncodeInvalidQType, "unknown or not supported QType");
            }

            int rdLength = buffer.Length - rdLengthOffset - 2;

            if (rdLength > ushort.MaxValue)
                throw new DnsException(DnsProtocolError.EncodeMaxRecordLengthExceeded);

            MemMap.ToBytes1UShortBE((ushort)rdLength, buffer.Buffer, rdLengthOffset);
        }

        public Question Decode_Question(BytesCursor cursor)
        {
            Question result = new Question();

            result.QName = Decode_DomainName(cursor);
            result.QType = (QType)BinConverter.ToUShortBE(cursor.Buffer, cursor.CurrentOffset);
            result.QClass = (QClass)BinConverter.ToUShortBE(cursor.Buffer, cursor.CurrentOffset + 2);

            cursor.CurrentOffset += 4;

            return result;
        }

        public Header Decode_Header(BytesCursor buffer)
        {
            if (buffer.Length < 12) throw new DnsException(DnsProtocolError.DecodeMinHeaderLength, "decode error: min header length < 12");

            Header header = new Header();
            header.Id = (ushort)(buffer[0] << 8 | buffer[1]);
            header.QR = (QRType)((buffer[2] & 0x80) >> 7);
            header.Opcode = (Opcode)((buffer[3] & 0x78) >> 3);
            header.AA = (buffer[2] & 0x04) == 1;
            header.TC = (buffer[2] & 0x02) == 1;
            header.RD = (buffer[2] & 0x01) == 1;
            header.RA = (buffer[3] & 0x80) == 1;

            if ((buffer[4] & 0x70) != 0)
                throw new DnsException(DnsProtocolError.DecodeZValudNotZero, "decode error, Z value in header is not zero");

            header.RCode = (ResponseCode)(buffer[3] & 0x0F);
            header.QDCount = BinConverter.ToUShortBE(buffer.Buffer, buffer.CurrentOffset + 4);
            header.ANCount = BinConverter.ToUShortBE(buffer.Buffer, buffer.CurrentOffset + 6);
            header.NSCount = BinConverter.ToUShortBE(buffer.Buffer, buffer.CurrentOffset + 8);
            header.ARCount = BinConverter.ToUShortBE(buffer.Buffer, buffer.CurrentOffset + 10);

            buffer.ShiftCurrentOffset(12);

            return header;
        }

        private void Encode_RDataAAAA(RDataAAAA rd, ByteBuffer buffer)
        {
            if (rd.IPv6 == null || rd.IPv6.Length != 16)
                throw new DnsException(DnsProtocolError.EncodeInvalidIpv6LengthOrNull);

            buffer.Append(rd.IPv6);
        }

        private void Encode_RDataMX(RDataMX rd, ByteBuffer buffer)
        {
            int i = buffer.AllocEnd(2);
            MemMap.ToBytes1UShortBE(rd.Preference, buffer.Buffer, i);
            EncodeDomainName(buffer, rd.Exchange);
        }

        private void Encode_RDataMINFO(RDataMINFO rd, ByteBuffer buffer)
        {
            EncodeDomainName(buffer, rd.RMailbx);
            EncodeDomainName(buffer, rd.EMailbx);
        }

        private void Encode_RDataHINFO(RDataHINFO rd, ByteBuffer buffer)
        {
            if (rd.CPU.Length > DnsConsts.MaxCharacterStringLength ||
                rd.OS.Length > DnsConsts.MaxCharacterStringLength)
            {
                throw new DnsException(DnsProtocolError.EncodeMaxCharStrLenght);
            }

            int i = buffer.AllocEnd(1 + rd.CPU.Length + 1 + rd.OS.Length);
            buffer[i] = (byte)rd.CPU.Length;
            i += 1;
            Encoding.ASCII.GetBytes(rd.CPU, 0, rd.CPU.Length, buffer.Buffer, i);
            i += rd.CPU.Length;
            
            buffer[i] = (byte)rd.OS.Length;
            i += 1;
            Encoding.ASCII.GetBytes(rd.OS, 0, rd.OS.Length, buffer.Buffer, i);
        }

        private void Encode_RDataWKS(RDataWKS rd, ByteBuffer buffer)
        {
            int i = buffer.AllocEnd(4);
            MemMap.ToBytes1UIntBE(rd.Address, buffer.Buffer, i);
            buffer.Append(rd.Protocol);
            buffer.Append(rd.Bitmap);
        }

        private void Encode_RDataNULL(RDataNULL rd, ByteBuffer buffer)
        {
            buffer.Append(rd.Anything);
        }

        private void Encode_RDataSOA(RDataSOA rd, ByteBuffer buffer)
        {
            EncodeDomainName(buffer, rd.MName);
            EncodeDomainName(buffer, rd.RName);
            int i = buffer.AllocEnd(5 * 4);

            MemMap.ToBytes1UIntBE(rd.Serial, buffer.Buffer, i);
            MemMap.ToBytes1UIntBE(rd.Refresh, buffer.Buffer, i + 4);
            MemMap.ToBytes1UIntBE(rd.Retry, buffer.Buffer, i + 8);
            MemMap.ToBytes1UIntBE(rd.Expire, buffer.Buffer, i + 12);
            MemMap.ToBytes1UIntBE(rd.Minimum, buffer.Buffer, i + 16);
        }

        private void Encode_RDataCNAME(RDataCNAME rd, ByteBuffer buffer)
        {
            EncodeDomainName(buffer, rd.CName);
        }

        private void Encode_RDataMF(RDataMF rd, ByteBuffer buffer)
        {
            EncodeDomainName(buffer, rd.MADName);
        }

        private void Encode_RDataMD(RDataMD rd, ByteBuffer buffer)
        {
            EncodeDomainName(buffer, rd.MADName);
        }

        private void Encode_RDataNS(RDataNS rd, ByteBuffer buffer)
        {
            EncodeDomainName(buffer, rd.NSDName);
        }

        private void EncodeDomainName(ByteBuffer buffer, string domainName)
        {
            if (domainName.Length + 1 > DnsConsts.MaxDomainNameLength)
                throw new DnsException(DnsProtocolError.EncodeMaxDomainNameLength, "encoded domain name exceed max allowed value: " + domainName);

            string[] qnameLabels = domainName.Split('.');
            int totalLabelLen = 0;
            int labelEncodeStart = buffer.Length;

            for (int i = 0; i < qnameLabels.Length; i++)
            {
                string label = qnameLabels[i];
                buffer.Append((byte)label.Length);


                if (label.Length > DnsConsts.MaxLabelLength || label.Length < 1)
                    throw new DnsException(DnsProtocolError.EncodeInvalidLabel, $"invalid label: '{qnameLabels[i]}'");

                for (int j = 0; j < qnameLabels[i].Length; j++)
                {
                    buffer.Append((byte)label[j]);
                }

                totalLabelLen += label.Length + 1;
            }

            buffer.Append(0);

            if (buffer.Length - labelEncodeStart > DnsConsts.MaxDomainNameLength)
                throw new DnsException(DnsProtocolError.EncodeMaxDomainNameLength, "encoding: total length of label exceed max");
        }

        private void Encode_RDataTXT(RDataTXT rd, ByteBuffer buffer)
        {
            foreach (string txt in rd.TxtData)
            {
                if (txt?.Length > DnsConsts.MaxCharacterStringLength)
                    throw new DnsException(DnsProtocolError.EncodeMaxCharStrLenght, $"rd.txtdata.length exceed max length for '{txt}'");

                buffer.Append((byte)txt.Length);
                int start = buffer.AllocEnd(txt.Length);
                Encoding.ASCII.GetBytes(txt, new Span<byte>(buffer.Buffer, start, txt.Length));
            }
        }

        private void Encode_RDataA(RDataA rd, ByteBuffer buffer)
        {
            buffer.AllocEnd(4);
            MemMap.ToBytes1UIntBE(rd.Address, buffer.Buffer, buffer.Length - 4);
        }

        private void Encode_Question(Question question, ByteBuffer buffer)
        {
            EncodeDomainName(buffer, question.QName);
            
            buffer.AllocEnd(4);
            MemMap.ToBytes1UShortBE((ushort)question.QType, buffer.Buffer, buffer.Length - 4);
            MemMap.ToBytes1UShortBE((ushort)question.QClass, buffer.Buffer, buffer.Length - 2);
        }


        // decoding

        public Message Decode(BytesCursor cursor, bool isTcp = false)
        {
            if (isTcp)
            {
                cursor.ShiftCurrentOffset(2);
            }

            Message result = new Message();
            Header header = Decode_Header(cursor);

            // todo: validate max no entries

            result.Question = new Question[header.QDCount];
            result.Answer = new ResourceRecord[header.ANCount];
            result.Authority = new ResourceRecord[header.NSCount];
            result.Additional = new ResourceRecord[header.ARCount];

            for (int i = 0; i < header.QDCount; i++)
            {
                result.Question[i] = Decode_Question(cursor);
            }

            for (int i = 0; i < header.ANCount; i++)
            {
                result.Answer[i] = Decode_ResourceRecord(cursor);
            }

            for (int i = 0; i < header.NSCount; i++)
            {
                result.Authority[i] = Decode_ResourceRecord(cursor);
            }

            for (int i = 0; i < header.ARCount; i++)
            {
                result.Additional[i] = Decode_ResourceRecord(cursor);
            }

            if (!cursor.IsValidEnd) throw new DnsException(DnsProtocolError.DecodeMsgLengthNotMatchTotalLength);

            result.Header = header;

            return result;
        }

        private RDataA Decode_RDataA(BytesCursor cursor)
        {
            if (cursor.Length < 4) throw new DnsException(DnsProtocolError.DecodeError, "RDataA length < 4");

            RDataA result = new RDataA(MemMap.ToUInt4BytesBE(cursor.Buffer, cursor.CurrentOffset));

            cursor.CurrentOffset += 4;

            return result;
        }

        private RDataNS Decode_RDataNS(BytesCursor cursor)
        {
            if (!cursor.HasData) throw new DnsException(DnsProtocolError.DecodeError, "RDataNS length < 1");

            string nsDomainName = Decode_DomainName(cursor);

            RDataNS result = new RDataNS(nsDomainName);

            return result;
        }

        private RDataMD Decode_RDataMD(BytesCursor cursor)
        {
            if (!cursor.HasData) throw new DnsException(DnsProtocolError.DecodeError, "RDataMD length < 1");

            string madName = Decode_DomainName(cursor);
            RDataMD result = new RDataMD(madName);

            return result;
        }

        private RDataMF Decode_RDataMF(BytesCursor cursor)
        {
            if (!cursor.HasData) throw new DnsException(DnsProtocolError.DecodeError, "RdataMF length < 1");

            string madName = Decode_DomainName(cursor);
            RDataMF result = new RDataMF(madName);

            return result;
        }

        private RDataCNAME Decode_RDataCNAME(BytesCursor cursor)
        {
            if (!cursor.HasData) throw new DnsException(DnsProtocolError.DecodeDomainName, "RData CNAME length == 0");

            string cname = Decode_DomainName(cursor);
            RDataCNAME result = new RDataCNAME(cname);

            return result;
        }

        private RDataSOA Decode_RDataSOA(BytesCursor cursor)
        {
            if (cursor.Length < 22) throw new DnsException(DnsProtocolError.DecodeError, "SOA record length < 22 but 22 i min");

            string mname = Decode_DomainName(cursor);
            string rname = Decode_DomainName(cursor);

            if (cursor.Length < 20) throw new DnsException(DnsProtocolError.DecodeError, "SOA record missing length for all fields");

            uint serial = MemMap.ToUInt4BytesBE(cursor.Buffer, cursor.CurrentOffset);
            uint refresh = MemMap.ToUInt4BytesBE(cursor.Buffer, cursor.CurrentOffset += 4);
            uint retry = MemMap.ToUInt4BytesBE(cursor.Buffer, cursor.CurrentOffset += 4);
            uint expire = MemMap.ToUInt4BytesBE(cursor.Buffer, cursor.CurrentOffset += 4);
            uint minimum = MemMap.ToUInt4BytesBE(cursor.Buffer, cursor.CurrentOffset += 4);

            cursor.CurrentOffset += 4;

            RDataSOA result = new RDataSOA()
            {
                MName = mname,
                RName = rname,
                Serial = serial,
                Retry = retry,
                Refresh = refresh,
                Expire = expire,
                Minimum = minimum
            };

            return result;
        }

        public RDataMB Decode_RDataMB(BytesCursor cursor)
        {
            if (!cursor.HasData) throw new DnsException(DnsProtocolError.DecodeError, "RDataMB cursor length == 0");

            string madName = Decode_DomainName(cursor);
            RDataMB result = new RDataMB(madName);

            return result;
        }

        public RDataMG Decode_RDataMG(BytesCursor cursor)
        {
            if (!cursor.HasData) throw new DnsException(DnsProtocolError.DecodeError, "RDataMG cursor len = 0");

            string madName = Decode_DomainName(cursor);
            RDataMG result = new RDataMG(madName);

            return result;
        }

        public RDataPTR Decode_RDataPTR(BytesCursor cursor)
        {
            if (!cursor.HasData) throw new DnsException(DnsProtocolError.DecodeError, "RDataPTR empty");

            string ptrName = Decode_DomainName(cursor);
            RDataPTR result = new RDataPTR(ptrName);

            return result;
        }

        public RDataHINFO Decode_RDataHINFO(BytesCursor cursor)
        {
            string cpu = Decode_CharacterString(cursor);
            string os = Decode_CharacterString(cursor);

            return new RDataHINFO(cpu, os);
        }

        public RDataMINFO Decode_RDataMINFO(BytesCursor cursor)
        {
            string rmailbx = Decode_DomainName(cursor);
            string emailbx = Decode_DomainName(cursor);

            return new RDataMINFO(rmailbx, emailbx);
        }

        public RDataMX Decode_RDataMX(BytesCursor cursor)
        {
            if (cursor.Length < 3) throw new DnsException(DnsProtocolError.DecodeError, "min length 3 of RdataMX");

            ushort preference = MemMap.ToUShort2BytesBE(cursor.Buffer, cursor.CurrentOffset);
            cursor.CurrentOffset += 2;
            string exchange = Decode_DomainName(cursor);

            return new RDataMX(preference, exchange);
        }

        public RDataTXT Decode_RDataTXT(BytesCursor cursor, int rdlength)
        {
            List<string> txt = new List<string>();
            
            int decoded = 0, stringStartOffset = cursor.CurrentOffset;

            while (decoded < rdlength)
            {
                string txtString = Decode_CharacterString(cursor);
                txt.Add(txtString);
                decoded += cursor.CurrentOffset - stringStartOffset;
                stringStartOffset = cursor.CurrentOffset;
            }

            return new RDataTXT(txt.ToArray());
        }

        public RDataAAAA Decode_RDataAAAA(BytesCursor cursor)
        {
            if (cursor.Length < 16) throw new DnsException(DnsProtocolError.DecodeError, "aaaa invalid length cursor.length < 16");

            byte[] ipv6 = new byte[16];
            Buffer.BlockCopy(cursor.Buffer, cursor.CurrentOffset, ipv6, 0, 16);

            cursor.CurrentOffset += 16;

            return new RDataAAAA(ipv6);
        }

        public RDataNULL Decode_RDataNULL(BytesCursor cursor, ushort length)
        {
            if (cursor.Length < length) throw new DnsException(DnsProtocolError.DecodeError, "RDataNULL: cursor length < rdata.length");

            byte[] result = new byte[length];

            Buffer.BlockCopy(cursor.Buffer, cursor.CurrentOffset, result, 0, length);
            cursor.CurrentOffset += length;

            return new RDataNULL(result);
        }

        public RDataMR Decode_RDataMR(BytesCursor cursor)
        {
            if (!cursor.HasData) throw new DnsException(DnsProtocolError.DecodeError, "RDataMG cursor len = 0");

            string newName = Decode_DomainName(cursor);
            RDataMR result = new RDataMR(newName);

            return result;
        }

        public string Decode_CharacterString(BytesCursor cursor)
        {
            if (!cursor.HasData) throw new DnsException(DnsProtocolError.DecodeError, "character string without 1-byte indicating length");

            int length = cursor[0];

            if (cursor.Length < length + 1) throw new DnsException(DnsProtocolError.DecodeError, "character string length exceed cursor length");
            
            cursor.CurrentOffset += 1;
            string result = Encoding.ASCII.GetString(cursor.Buffer, cursor.CurrentOffset, length);
            cursor.CurrentOffset += length;

            return result;
        }

        private ResourceRecord Decode_ResourceRecord(BytesCursor cursor)
        {
            var rr = new ResourceRecord();

            rr.Name = Decode_DomainName(cursor);
            rr.Type = (QType)MemMap.ToUShort2BytesBE(cursor.Buffer, cursor.CurrentOffset);
            rr.Class = (QClass)MemMap.ToUShort2BytesBE(cursor.Buffer, cursor.CurrentOffset += 2);
            rr.TTL = MemMap.ToUInt4BytesBE(cursor.Buffer, cursor.CurrentOffset += 2);
            rr.RDLength = MemMap.ToUShort2BytesBE(cursor.Buffer, cursor.CurrentOffset += 4);
            cursor.CurrentOffset += 2;

            object rdata = null;

            switch (rr.Type)
            {
                case QType.A: rdata = Decode_RDataA(cursor); break;
                case QType.NS: rdata = Decode_RDataNS(cursor); break;
                case QType.MD: rdata = Decode_RDataMD(cursor); break;
                case QType.MF: rdata = Decode_RDataMF(cursor); break; 
                case QType.CNAME: rdata = Decode_RDataCNAME(cursor); break;
                case QType.SOA: rdata = Decode_RDataSOA(cursor); break;
                case QType.MB: rdata = Decode_RDataMB(cursor); break;
                case QType.MG: rdata = Decode_RDataMG(cursor); break;
                case QType.MR: rdata = Decode_RDataMR(cursor); break; 
                case QType.PTR: rdata = Decode_RDataPTR(cursor); break;
                case QType.HINFO: rdata = Decode_RDataHINFO(cursor); break;
                case QType.MINFO: rdata = Decode_RDataMINFO(cursor); break;
                case QType.MX: rdata = Decode_RDataMX(cursor); break;
                case QType.TXT: rdata = Decode_RDataTXT(cursor, rr.RDLength); break;
                case QType.AAAA: rdata = Decode_RDataAAAA(cursor); break;
                case QType.NULL: rdata = Decode_RDataNULL(cursor, rr.RDLength); break;
                case QType.WKS: rdata = Decode_RDataWKS(cursor, rr.RDLength); break;
                case QType.MAILB: 
                case QType.MAILA:
                case QType.AXFR:
                case QType.All:
                    throw new DnsException(DnsProtocolError.DecodeError, $"invalid qtype of resource record: {rr.Type} ({(int)rr.Type})");
                // wsk or anything unknown as byte array
                default:
                    if (cursor.Length < rr.RDLength) throw new DnsException(DnsProtocolError.DecodeError, "rdlength exceed current length");
                    
                    byte[] rawRData = new byte[rr.RDLength];
                    Buffer.BlockCopy(cursor.Buffer, cursor.CurrentOffset, rawRData, 0, rr.RDLength);
                    rdata = rawRData;
                    cursor.CurrentOffset += rr.RDLength;
                    break;
            }

            Debug.Assert(rdata != null);

            rr.RData = rdata;

            return rr;
        }

        private RDataWKS Decode_RDataWKS(BytesCursor cursor, ushort rdlength)
        {
            byte[] bitmap;

            if (cursor.Length < rdlength) throw new DnsException(DnsProtocolError.DecodeError, "rdatawks cursor.Length < rdlength");
            if (cursor.Length < 5) throw new DnsException(DnsProtocolError.DecodeError, "rdatawks: length < 5 (5 is min)");

            bitmap = new byte[rdlength - 5];

            if (rdlength > 5) Buffer.BlockCopy(cursor.Buffer, cursor.CurrentOffset + 5, bitmap, 0, rdlength - 5);

            RDataWKS result = new RDataWKS()
            {
                Address = MemMap.ToUInt4BytesBE(cursor.Buffer, cursor.CurrentOffset),
                Protocol = cursor[4],
                Bitmap = bitmap,
            };

            cursor.CurrentOffset += rdlength;

            return result;
        }

        private string Decode_DomainName(BytesCursor cursor)
        {
            List<string> labels = new List<string>();

            if (!cursor.HasData) throw new DnsException(DnsProtocolError.DecodeDomainName, "no data for domain name");

            int labelOffset = cursor.CurrentOffset;
            int labelLength = -1;
            bool compressedModeInitialized = false;

            while (cursor.Buffer[labelOffset] != 0)
            {
                if ((cursor.Buffer[labelOffset] & 0xC0) == 0xC0)
                {
                    if (cursor.Length < 2)
                        throw new DnsException(DnsProtocolError.DecodeDomainName, "DecodeInvalidPtrValueMin2BytesLen");

                    labelOffset = (cursor.Buffer[labelOffset] << 8 | cursor.Buffer[labelOffset + 1] << 0) & 0x3FFF; // remove first two MSB

                    if (!compressedModeInitialized) cursor.CurrentOffset += 2;
                    compressedModeInitialized = true;
                }
                else
                {
                    if (!cursor.OffsetInStartEnd(labelOffset))
                        throw new DnsException(DnsProtocolError.DecodeDomainName, "invalid label offset not in cursor range");

                    labelLength = cursor.Buffer[labelOffset];

                    if (labelLength > DnsConsts.MaxLabelLength) throw new DnsException(DnsProtocolError.DecodeInvalidLabelLength, "max label length");
                    if (!cursor.OffsetInStartEnd(labelOffset + labelLength)) throw new DnsException(DnsProtocolError.DecodeInvalidLabelLength, "outside of bounds");

                    string label = Encoding.ASCII.GetString(cursor.Buffer, labelOffset + 1, labelLength);
                    labels.Add(label);

                    labelOffset += labelLength + 1;
                    if (!compressedModeInitialized) cursor.CurrentOffset += labelLength + 1;
                }
            }

            // add last '0' - in this case we had a sequence of labels without pointer
            if (!compressedModeInitialized) cursor.CurrentOffset += 1;

            return string.Join(".", labels);
        }

        public static bool DnsNameEquals(string name1, string name2)
        {
            if (name1 == name2) return true;
            if (name1 != null || name2 != null) return false;

            return string.Compare(name1, name2, true) == 0;
        }

       

        public static uint Ipv4ToUInt(string ipv4)
        {
            string[] parts = ipv4.Split('.');

            return
                uint.Parse(parts[0]) << 24 |
                uint.Parse(parts[1]) << 16 |
                uint.Parse(parts[2]) << 08 |
                uint.Parse(parts[3]) << 0;
        }
    }
}
