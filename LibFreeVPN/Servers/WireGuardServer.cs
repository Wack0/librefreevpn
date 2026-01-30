using IniParser.Parser;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace LibFreeVPN.Servers
{
    public sealed class WireGuardServer : VPNServerBase<WireGuardServer, WireGuardServer.Parser>
    {
        public sealed class Parser : VPNServerConfigParserFullBase<WireGuardServer>
        {
            public override WireGuardServer CreateInstance(string config)
                => new WireGuardServer(config);

            public override WireGuardServer CreateInstance(string config, string hostname, string port)
                => new WireGuardServer(config, hostname, port);

            public override WireGuardServer CreateInstance(string config, IReadOnlyDictionary<string, string> extraRegistry)
                => new WireGuardServer(config, extraRegistry);

            public override WireGuardServer CreateInstance(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry)
                => new WireGuardServer(config, hostname, port, extraRegistry);

            public override WireGuardServer CreateInstance(string hostname, string port)
            {
                throw new NotSupportedException();
            }

            public override WireGuardServer CreateInstance(string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry)
            {
                throw new NotSupportedException();
            }

            public override bool CanCreateInstance(bool withConfig)
                => withConfig;


            private static IniDataParser s_IniParser = new IniDataParser();

            private static char[] s_SplitKv = { '=' };

            static Parser()
            {
                s_IniParser.Configuration.SkipInvalidLines = true;
                s_IniParser.Configuration.CommentString = "#";
            }

            private static int SubstringCount(string haystack, string needle)
            {
                return (haystack.Length - haystack.Replace(needle, string.Empty).Length) / needle.Length;
            }

            private (string config, string hostname, string port) ParseConfigSingle(string config)
            {
                var iniData = s_IniParser.Parse(config);

                var addr = iniData["Peer"]["Endpoint"].Split(':');
                return (config, addr[0], addr[1]);
            }

            public override IEnumerable<(string config, string hostname, string port)> ParseConfigFull(string config)
            {

                var count = SubstringCount(config, "[Peer]");
                if (count == 0) return Enumerable.Empty<(string config, string hostname, string port)>();
                else if (count == 1)
                {
                    // Single Peer, just parse the whole thing
                    return ParseConfigSingle(config).EnumerableSingle();
                }

                // Multiple Peers
                // take the config and split it by newline
                var split = config.Split(ServerUtilities.NewLines, StringSplitOptions.None);

                // remove all lines starting with comment
                {
                    var splitList = new List<string>();
                    for (int i = 0; i < split.Length; i++)
                    {
                        var line = split[i];
                        if (line.Length > 0 && line[0] == '#') continue;
                        splitList.Add(line);
                    }
                    split = splitList.ToArray();
                }

                // walk through the split config, and create "clean" config (with no servers), "servers" (containing just the servers)
                var configClean = new List<string>();
                var servers = new List<string>();

                StringBuilder sb = null;
                for (int i = 0; i < split.Length; i++)
                {
                    if (split[i][0] == '[' && split[i].Last() == ']')
                    {
                        if (sb != null) servers.Add(sb.ToString());
                        if (split[i].Substring(1, -1).Trim() == "Peer")
                        {
                            sb = new StringBuilder();
                        }
                        else
                        {
                            sb = null;
                        }
                    }
                    if (sb == null) configClean.Add(split[i]);
                    else sb.AppendLine(split[i]);
                }

                // for each server, take a copy of the configClean, add the server in, yield return it
                return servers.SelectMany((server) =>
                {
                    var thisConfig = new List<string>(configClean);
                    thisConfig.AddRange(server.Split(ServerUtilities.NewLines, StringSplitOptions.None));
                    return ParseConfigSingle(string.Join("\r\n", thisConfig.ToArray())).EnumerableSingle();
                }).ToList();
            }
        }

        public override ServerProtocol Protocol => ServerProtocol.WireGuard;


        public WireGuardServer(string config) : base(config)
        {
        }

        public WireGuardServer(string config, string hostname, string port) : base(config, hostname, port)
        {
        }

        public WireGuardServer(string config, IReadOnlyDictionary<string, string> extraRegistry) : base(config, extraRegistry)
        {
        }

        public WireGuardServer(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry) : base(config, hostname, port, extraRegistry)
        {
        }
    }
}