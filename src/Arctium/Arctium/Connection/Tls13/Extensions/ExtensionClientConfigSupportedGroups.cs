using Arctium.Shared.Other;
using Arctium.Standards.Connection.Tls13;
using System;
using System.Linq;
using Arctium.Standards.Connection.Tls13Impl;
using Arctium.Standards.Connection.Tls13Impl.Model.Extensions;

namespace Arctium.Standards.Connection.Tls13.Extensions
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
