using System;
using System.Collections.Generic;
using System.Text;

namespace LibFreeVPN
{
    /// <summary>
    /// Defines a parser for a VPN server configuration.
    /// </summary>
    public interface IVPNServerConfigParser
    {
        /// <summary>
        /// Parses configuration data for a iterable collection of hostname/port tuples.
        /// </summary>
        /// <param name="config">Configuration string</param>
        /// <returns>Iterable collection of hostname/port tuples</returns>
        IEnumerable<(string hostname, string port)> ParseConfig(string config);

        /// <summary>
        /// Parses configuration data for a iterable collection of config/hostname/port tuples.
        /// </summary>
        /// <param name="config">Configuration string</param>
        /// <returns>Iterable collection of config/hostname/port tuples</returns>
        IEnumerable<(string config, string hostname, string port)> ParseConfigFull(string config);

        /// <summary>
        /// Given a parsed config, and server registry data, get the final user visible config.
        /// </summary>
        /// <param name="config">Parsed config</param>
        /// <param name="registry">Registry data</param>
        /// <returns>User visible config</returns>
        string GetUserVisibleConfig(string config, IReadOnlyDictionary<string, string> registry);

        /// <summary>
        /// Given an unparsed config, add any extra registry data that is common to this server type.
        /// </summary>
        /// <param name="registry">Registry data</param>
        /// <param name="config">Unparsed config</param>
        void AddExtraProperties(IDictionary<string, string> registry, string config);
    }

    public interface IVPNServerConfigParser<TServer> : IVPNServerConfigParser
        where TServer : IVPNServer
    {
        TServer CreateInstance(string config);

        TServer CreateInstance(string config, string hostname, string port);

        TServer CreateInstance(string config, IReadOnlyDictionary<string, string> extraRegistry);
        TServer CreateInstance(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry);

        TServer CreateInstance(string hostname, string port);

        TServer CreateInstance(string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry);

        bool CanCreateInstance(bool withConfig);
    }
}
