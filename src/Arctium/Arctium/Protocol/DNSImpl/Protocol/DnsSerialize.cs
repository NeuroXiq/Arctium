using Arctium.Protocol.DNS;
using Arctium.Protocol.DNSImpl.Model;
using Arctium.Shared;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Arctium.Protocol.DNSImpl.Protocol
{
    public class DnsSerialize
    {
        public DnsSerialize()
        { }

        // encoding

        public void Encode(Message message, ByteBuffer buffer)
        {
            Header h = message.Header;

            buffer.AllocEnd(12);
            MemMap.ToBytes1UShortBE(h.Id, buffer.Buffer, 0);

            buffer[2] =(byte)(
                (((byte)h.QR) << 7) |
                ((byte)h.Opcode << 6) |
                ((h.AA ? 1 : 0) << 2) |
                ((h.TC ? 1 : 0) << 1) |
                ((h.RD ? 1 : 0) << 0));

            buffer[3] = (byte)
                (
                    (h.Z << 4) |
                    ((byte)h.RCode << 0) | 0
                );

            MemMap.ToBytes1UShortBE(h.QDCount, buffer.Buffer, 4);
            MemMap.ToBytes1UShortBE(h.ANCount, buffer.Buffer, 6);
            MemMap.ToBytes1UShortBE(h.NSCount, buffer.Buffer, 8);
            MemMap.ToBytes1UShortBE(h.ARCount, buffer.Buffer, 10);

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

            // MemDump.HexDump(buffer.Buffer, 0, buffer.DataLength, 1, 2);
        }

        private void Encode_ResourceRecord(ResourceRecord rr, ByteBuffer buffer)
        {
            // +2 one byte of length and one zero byte at the end
            if (rr.Name.Length + 2 > DnsConsts.MaxDomainNameLength)
                throw new DnsException("ResourceRecord.Name.Length + 1 > TotalLengthOfDomainName");

            buffer.Append((byte)rr.Name.Length);
            foreach (var c in rr.Name) buffer.Append((byte)c);
            buffer.Append(0);

            int i = buffer.DataLength;
            buffer.AllocEnd(10);
            MemMap.ToBytes1UShortBE((ushort)rr.Type, buffer.Buffer, i);
            MemMap.ToBytes1UShortBE((ushort)rr.Class, buffer.Buffer, i + 2);
            MemMap.ToBytes1IntBE((ushort)rr.TTL, buffer.Buffer, i + 4);
            int rdLengthOffset = i + 8;
            

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
                case QType.AXFR:
                case QType.MAILB:
                case QType.MAILA:
                case QType.All:
                    throw new NotImplementedException("Cannot encode this because QType is only for queries");
                default: throw new DnsException("invalid QType resource record encode");
            }

            ushort rdLength = (ushort)(buffer.DataLength - rdLengthOffset - 2);

            MemMap.ToBytes1UShortBE(rdLength, buffer.Buffer, rdLengthOffset);
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
            if (rd.CPU.Length + 1 > DnsConsts.MaxCharacterStringLength ||
                rd.OS.Length + 1 > DnsConsts.MaxCharacterStringLength)
            {
                throw new DnsException(DnsOtherError.SerializeInvalidCharacterStringLength);
            }

            int i = buffer.AllocEnd((1 + rd.CPU.Length + 1 + rd.OS.Length));
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
            MemMap.ToBytes1IntBE(rd.Refresh, buffer.Buffer, i + 4);
            MemMap.ToBytes1IntBE(rd.Retry, buffer.Buffer, i + 8);
            MemMap.ToBytes1IntBE(rd.Expire, buffer.Buffer, i + 12);
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
                throw new DnsException("encoded domain name exceed max allowed value: " + domainName);

            string[] qnameLabels = domainName.Split('.');
            int totalLabelLen = 0;
            int labelEncodeStart = buffer.DataLength;

            for (int i = 0; i < qnameLabels.Length; i++)
            {
                string label = qnameLabels[i];
                buffer.Append((byte)label.Length);


                if (label.Length > DnsConsts.MaxLabelLength || label.Length < 1)
                    throw new DnsException($"invalid label: '{qnameLabels[i]}'");

                for (int j = 0; j < qnameLabels[i].Length; j++)
                {
                    buffer.Append((byte)label[j]);
                }

                totalLabelLen += label.Length + 1;
            }

            buffer.Append(0);

            if (buffer.DataLength - labelEncodeStart > DnsConsts.MaxDomainNameLength)
                throw new DnsException("encoding: total length of label exceed max");
        }

        private void Encode_RDataTXT(RDataTXT rd, ByteBuffer buffer)
        {
            if (rd.TxtData.Length + 1 > DnsConsts.MaxCharacterStringLength)
                throw new DnsException("rd.txtdata.length exceed max length");

            buffer.Append((byte)rd.TxtData.Length);
            int start = buffer.AllocEnd(rd.TxtData.Length);
            Encoding.ASCII.GetBytes(rd.TxtData, new Span<byte>(buffer.Buffer, start, rd.TxtData.Length));
        }

        private void Encode_RDataA(RDataA rd, ByteBuffer buffer)
        {
            buffer.AllocEnd(4);
            MemMap.ToBytes1UIntBE(rd.Address, buffer.Buffer, buffer.DataLength - 4);
        }

        private void Encode_Question(Question question, ByteBuffer buffer)
        {
            EncodeDomainName(buffer, question.QName);
            
            buffer.AllocEnd(4);
            MemMap.ToBytes1UShortBE((ushort)question.QType, buffer.Buffer, buffer.DataLength - 4);
            MemMap.ToBytes1UShortBE((ushort)question.QClass, buffer.Buffer, buffer.DataLength - 2);
        }


        // decoding

        public Message Decode(BytesSpan buffer)
        {
            Message result = new Message();
            Header header = Decode_Header(buffer, out int decodedLength);
            buffer.ShiftOffset(decodedLength);

            // todo: validate max no entries

            result.Question = new Question[header.QDCount];
            result.Answer = new ResourceRecord[header.ANCount];
            result.Authority = new ResourceRecord[header.NSCount];
            result.Additional = new ResourceRecord[header.ARCount];

            for (int i = 0; i < header.QDCount; i++)
            {
                result.Question[i] = Decode_Question(buffer, out decodedLength);
                buffer.ShiftOffset(decodedLength);
            }

            for (int i = 0; i < header.ANCount; i++)
            {
                throw new NotImplementedException();
            }

            for (int i = 0; i < header.NSCount; i++)
            {
                throw new NotImplementedException();
            }

            for (int i = 0; i < header.ARCount; i++)
            {
                throw new NotImplementedException();
            }

            if (buffer.Offset != buffer.Length) throw new DnsException(DnsProtocolError.DecodeMsgLengthNotMatchTotalLength);

            result.Header = header;

            return result;
        }

        private Question Decode_Question(BytesSpan buffer, out int decodedLength)
        {
            Question result = new Question();
            int i = 0;
            List<string> labels = new List<string>();

            while (buffer[i] > 0)
            {
                int labelLengt = buffer[i];

                if (labelLengt > DnsConsts.MaxLabelLength) throw new DnsException(DnsProtocolError.DecodeInvalidLabelLength);
                if (i + buffer.Offset >= buffer.Length) throw new DnsException(DnsProtocolError.DecodeInvalidLabelLength);

                if (labelLengt > 0)
                    labels.Add(Encoding.ASCII.GetString(buffer.Buffer, buffer.GetIndex(i + 1), labelLengt));

                i += labelLengt + 1;

                if (i > DnsConsts.MaxDomainNameLength)
                    throw new DnsException(DnsProtocolError.TotalLengthOfDomainNameExceeded);
            }
            
            i += 1;

            result.QName = string.Join('.', labels);
            result.QType = (QType)BinConverter.ToUShortBE(buffer.Buffer, buffer.GetIndex(i));
            result.QClass = (QClass)BinConverter.ToUShortBE(buffer.Buffer, buffer.GetIndex(i + 2));

            i += 4;

            decodedLength = i;
            return result;
        }

        private Header Decode_Header(BytesSpan buffer, out int decodedLength)
        {
            if (buffer.Length < 12) throw new DnsException("decode error: min header length < 12");

            Header header = new Header();
            header.Id = (ushort)(buffer[0] << 8 | buffer[1]);
            header.QR = (QRType)((buffer[2] & 0x80) >> 7);
            header.Opcode = (Opcode)((buffer[3] & 0x78) >> 3);
            header.AA = (buffer[2] & 0x04) == 1;
            header.TC = (buffer[2] & 0x02) == 1;
            header.RD = (buffer[2] & 0x01) == 1;
            header.RA = (buffer[3] & 0x80) == 1;

            if ((buffer[4] & 0x70) != 0) throw new DnsException("decode error, Z value in header is not zero");
            
            header.RCode = (ResponseCode)(buffer[3] & 0x0F);
            header.QDCount = BinConverter.ToUShortBE(buffer.Buffer, buffer.Offset + 4);
            header.ANCount = BinConverter.ToUShortBE(buffer.Buffer, buffer.Offset + 6);
            header.NSCount = BinConverter.ToUShortBE(buffer.Buffer, buffer.Offset + 8);
            header.ARCount = BinConverter.ToUShortBE(buffer.Buffer, buffer.Offset + 10);

            decodedLength = 12;

            return header;
        }

        public static uint Ipv4ToUInt(string ipv4)
        {
            string[] parts = ipv4.Split('.');
            return
                ((uint)int.Parse(parts[0]) << 24) |
                ((uint)int.Parse(parts[1]) << 16) |
                ((uint)int.Parse(parts[2]) << 08) |
                ((uint)int.Parse(parts[3]) << 0);
        }
    }
}
