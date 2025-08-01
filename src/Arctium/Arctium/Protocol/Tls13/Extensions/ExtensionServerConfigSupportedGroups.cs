using Arctium.Shared;
using Arctium.Protocol.Tls13;
using System;
using System.Linq;
using Arctium.Protocol.Tls13Impl.Model.Extensions;

namespace Arctium.Protocol.Tls13.Extensions
{
    /// <summary>
    /// Configures 'Supported Groups' extension on server side 
    /// Server will use groups only listed here. If client do not support
    /// this groups then handshakefailure
    /// here
    /// </summary>
    public class ExtensionServerConfigSupportedGroups
    {
        public ReadOnlyMemory<NamedGroup> NamedGroups { get; private set; }

        internal SupportedGroupExtension.NamedGroup[] InternalNamedGroups { get; private set; }

        public ExtensionServerConfigSupportedGroups(NamedGroup[] namedGroupsList)
        {
            Validation.NotEmpty(namedGroupsList, nameof(namedGroupsList));
            Validation.EnumValueDefined(namedGroupsList, nameof(namedGroupsList));

            InternalNamedGroups = namedGroupsList
                .Select(g => (SupportedGroupExtension.NamedGroup)g)
                .ToArray();
        }
    }
}
