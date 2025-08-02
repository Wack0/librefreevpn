using System;
using System.Collections.Generic;
using System.Text;

namespace LibFreeVPN
{
    /// <summary>
    /// Describes a VPN server.
    /// </summary>
    public interface IVPNServer : IEquatable<IVPNServer>
    {
        /// <summary>
        /// Protocol of this VPN server
        /// </summary>
        ServerProtocol Protocol { get; }

        /// <summary>
        /// Configuration of this VPN server, format is dependent on the protocol type.
        /// </summary>
        string Config { get; }

        /// <summary>
        /// Key-value store describing information that may or may not be in the configuration. Dependent on the protocol type, but generally would include keys like host, port, username, password.
        /// </summary>
        IReadOnlyDictionary<string, string> Registry { get; }
        
    }
}
