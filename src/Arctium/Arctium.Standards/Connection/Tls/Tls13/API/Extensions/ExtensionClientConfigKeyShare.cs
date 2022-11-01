using Arctium.Shared.Other;
using System.Linq;

namespace Arctium.Standards.Connection.Tls.Tls13.API.Extensions
{
    /// <summary>
    /// Configures KeyShare extension (RFC 8446) on client side.
    /// For all groups configured here client will generate private key and public key pair
    /// and will sent it to server. This is possible to configure empty array,
    /// then server will choose a group and HelloRetryRequest will be performed.
    /// Expected usage is to include only one group in the list (because key pairs generation is expensive)
    /// for example list only with one group X25519.
    /// </summary>
    public class ExtensionClientConfigKeyShare
    {
        internal Model.Extensions.SupportedGroupExtension.NamedGroup[] InternalNamedGroups { get; private set; }

        public ExtensionClientConfigKeyShare(NamedGroup[] groups)
        {
            Validation.NotNull(groups, nameof(groups));
            Validation.EnumValueDefined(groups, nameof(groups));

            InternalNamedGroups = groups.Select(g => (Model.Extensions.SupportedGroupExtension.NamedGroup)g).ToArray();
        }
    }
}
