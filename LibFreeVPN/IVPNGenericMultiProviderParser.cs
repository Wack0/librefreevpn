using System;
using System.Collections.Generic;
using System.Text;

namespace LibFreeVPN
{
    public interface IVPNGenericMultiProviderParser
    {
        /// <summary>
        /// Parse a config of a generic multi-provider client, and return a list of servers.
        /// </summary>
        /// <param name="config">Config to parse</param>
        /// <param name="extraRegistry">Registry data</param>
        /// <returns>An iterator over a collection of VPN servers</returns>
        IEnumerable<IVPNServer> Parse(string config, IReadOnlyDictionary<string, string> extraRegistry);
    }
}
