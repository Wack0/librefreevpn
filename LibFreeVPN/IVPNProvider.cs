using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace LibFreeVPN
{
    /// <summary>
    /// Describes a VPN provider, that is, some remote service that provides VPN servers.
    /// </summary>
    public interface IVPNProvider
    {
        /// <summary>
        /// User-visible name
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Source of the sample reversed to initially understand this implemention.
        /// Should be link to app store (for phone app), link to sample (for PC app), etc.
        /// Slight obfuscation (rot13, base64 etc) of implementor's choice can be performed on sample source if wanted :)
        /// </summary>
        string SampleSource { get; }

        /// <summary>
        /// Version number of the sample reversed to initially understand this implemention.
        /// For phone app, should be version number reported by app store. Otherwise, version number reported by application, or modified date / build date of executable.
        /// </summary>
        string SampleVersion { get; }

        /// <summary>
        /// When true, calling GetServersAsync will involve network requests to servers ran by the developers of the sample, or entities involved with them.<br/>
        /// When false, network requests made by GetServersAsync are only to servers not directly ran by the sample developers, for example large public git forges (github/gitlab), blog hosting (wordpress.com/blogger/blogspot), social networks, etc.
        /// </summary>
        bool RiskyRequests { get; }

        /// <summary>
        /// Returns false if the list of servers is known ahead of time (that is, without any network request) to not contain at least one server with the specified protocol.
        /// Otherwise, returns true.
        /// </summary>
        /// <param name="protocol">Protocol type to check</param>
        /// <returns>True if the list of servers is known to contain at least one server of <paramref name="protocol"/>, false otherwise.</returns>
        bool HasProtocol(ServerProtocol protocol);

        /// <summary>
        /// Asynchronous method for obtaining the list of servers from this provider..
        /// </summary>
        /// <returns>Task object representing the asynchronous operation. On success, returns an iterator over a collection of VPN servers.</returns>
        Task<IEnumerable<IVPNServer>> GetServersAsync();
    }
}
