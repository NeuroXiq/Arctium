using Arctium.Shared;
using Arctium.Protocol.Tls13;
using System;
using System.Linq;
using Arctium.Protocol.Tls13Impl;
using Arctium.Protocol.Tls13Impl.Model.Extensions;

namespace Arctium.Protocol.Tls13.Extensions
{
    /// <summary>
    /// Configures 'Supported Groups' extension for client (client will sent 'supported groups 
    /// extension with values configured in this class)
    /// It also configures all allowed groups for key exchange on client side,
    /// so server will not be able to negotiate other groups that specified
    /// here
    /// </summary>
    public class ExtensionClientConfigSupportedGroups
    {
        public ReadOnlyMemory<NamedGroup> NamedGroups { get; private set; }

        internal SupportedGroupExtension.NamedGroup[] InternalNamedGroups { get; private set; }

        public ExtensionClientConfigSupportedGroups(NamedGroup[] namedGroupsList)
        {
            Validation.NotEmpty(namedGroupsList, nameof(namedGroupsList));
            Validation.EnumValueDefined(namedGroupsList, nameof(namedGroupsList));

            InternalNamedGroups = namedGroupsList
                .Select(g => (SupportedGroupExtension.NamedGroup)g)
                .ToArray();
        }
    }
}
