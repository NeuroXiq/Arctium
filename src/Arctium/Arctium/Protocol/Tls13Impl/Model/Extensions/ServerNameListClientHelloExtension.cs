﻿using System.Text;
using Arctium.Protocol.Tls13Impl.Model;

namespace Arctium.Protocol.Tls13Impl.Model.Extensions
{
    internal class ServerNameListClientHelloExtension : Extension
    {
        public override ExtensionType ExtensionType => ExtensionType.ServerName;

        public enum NameTypeEnum : byte
        {
            HostName
        }

        public ServerName[] ServerNameList { get; private set; }

        public ServerNameListClientHelloExtension(ServerName[] serverNameList)
        {
            ServerNameList = serverNameList;
        }

        public class ServerName
        {
            public NameTypeEnum NameType { get; private set; }
            public byte[] HostName { get; private set; }
            public string HostNameString { get; private set; }

            public ServerName(NameTypeEnum nameType, byte[] hostName)
            {
                NameType = nameType;
                HostName = hostName;
                HostNameString = Encoding.ASCII.GetString(hostName);
            }
        }
    }
}
