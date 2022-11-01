using Arctium.Shared.Other;
using System;
using System.Linq;

namespace Arctium.Standards.Connection.Tls.Tls13.API.Extensions
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

        internal Model.Extensions.SupportedGroupExtension.NamedGroup[] InternalNamedGroups { get; private set; }

        public ExtensionServerConfigSupportedGroups(NamedGroup[] namedGroupsList)
        {
            Validation.NotEmpty(namedGroupsList, nameof(namedGroupsList));
            Validation.EnumValueDefined(namedGroupsList, nameof(namedGroupsList));

            InternalNamedGroups = namedGroupsList
                .Select(g => (Model.Extensions.SupportedGroupExtension.NamedGroup)g)
                .ToArray();
        }
    }
}
