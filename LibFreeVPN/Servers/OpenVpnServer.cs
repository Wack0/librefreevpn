using System;
using System.Collections.Generic;
using System.Text;

namespace LibFreeVPN.Servers
{
    public sealed class OpenVpnServer : VPNServerBase<OpenVpnServer, OpenVpnServer.Parser>
    {
        public sealed class Parser : VPNServerConfigParserFullBase<OpenVpnServer>
        {
            public override OpenVpnServer CreateInstance(string config)
                => new OpenVpnServer(config);

            public override OpenVpnServer CreateInstance(string config, string hostname, string port)
                => new OpenVpnServer(config, hostname, port);

            public override OpenVpnServer CreateInstance(string config, IReadOnlyDictionary<string, string> extraRegistry)
                => new OpenVpnServer(config, extraRegistry);

            public override OpenVpnServer CreateInstance(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry)
                => new OpenVpnServer(config, hostname, port, extraRegistry);

            public override OpenVpnServer CreateInstance(string hostname, string port)
            {
                throw new NotSupportedException();
            }

            public override OpenVpnServer CreateInstance(string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry)
            {
                throw new NotSupportedException();
            }

            public override bool CanCreateInstance(bool withConfig)
                => withConfig;

            public override string GetUserVisibleConfig(string config, IReadOnlyDictionary<string, string> registry)
            {
                bool gotUsername = registry.TryGetValue(ServerRegistryKeys.Username, out var username);
                bool gotPassword = registry.TryGetValue(ServerRegistryKeys.Password, out var password);
                if (!gotUsername && !gotPassword) return config;
                var sb = new StringBuilder();
                if (gotUsername)
                {
                    sb.AppendFormat("# Username: {0}", username);
                    sb.AppendLine();
                }
                if (gotPassword)
                {
                    sb.AppendFormat("# Password: {0}", password);
                    sb.AppendLine();
                }
                sb.Append(config);
                return sb.ToString();
            }

            public override IEnumerable<(string config, string hostname, string port)> ParseConfigFull(string config)
            {
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

                // walk through the split config, and create "clean" config (with no servers), "servers" (containing just the servers), "server index" (arr index of first server)
                var configClean = new List<string>();
                var servers = new List<string>();
                var serverIdx = -1;

                for (int i = 0; i < split.Length; i++)
                {
                    var tokenIdx = split[i].IndexOf(' ');
                    if (tokenIdx != -1 && split[i].Substring(0, tokenIdx).ToLower() == "remote")
                    {
                        if (serverIdx == -1) serverIdx = i;
                        servers.Add(split[i]);
                    }
                    else
                    {
                        configClean.Add(split[i]);
                    }
                }

                // for each server, take a copy of the configClean, add the server in, yield return it
                foreach (var server in servers)
                {
                    var thisConfig = new List<string>(configClean);
                    thisConfig.Insert(serverIdx, server);

                    var serverCommentIdx = server.IndexOf('#');
                    var cleanServer = server;
                    if (serverCommentIdx != -1) cleanServer = server.Substring(0, serverCommentIdx);
                    var splitServer = cleanServer.Split(' ');
                    if (splitServer.Length < 3) continue;

                    yield return (string.Join("\r\n", thisConfig.ToArray()), splitServer[1], splitServer[2]);
                }
                yield break;
            }
        }
        public OpenVpnServer(string config) : base(config)
        {
        }

        public OpenVpnServer(string config, string hostname, string port) : base(config, hostname, port)
        {
        }

        public OpenVpnServer(string config, IReadOnlyDictionary<string, string> extraRegistry) : base(config, extraRegistry)
        {
        }

        public OpenVpnServer(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry) : base(config, hostname, port, extraRegistry)
        {
        }

        public override ServerProtocol Protocol => ServerProtocol.OpenVPN;

        public static string InjectHostIntoConfig(string config, string hostname, string port)
        {
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

            // walk through the split config, and create "clean" config (with no servers), "servers" (containing just the servers), "server index" (arr index of first server)
            var configClean = new List<string>();
            //var servers = new List<string>();
            var serverIdx = -1;
            var protoIdx = -1;

            for (int i = 0; i < split.Length; i++)
            {
                var tokenIdx = split[i].IndexOf(' ');
                if (tokenIdx != -1 && split[i].Substring(0, tokenIdx).ToLower() == "remote")
                {
                    if (serverIdx == -1) serverIdx = i;
                    //servers.Add(split[i]);
                }
                else
                {
                    if (protoIdx == -1 && tokenIdx != -1 && split[i].Substring(0, tokenIdx).ToLower() == "proto")
                        protoIdx = i;
                    configClean.Add(split[i]);
                }
            }

            if (serverIdx == -1)
            {
                // No server was found, so use the protoIdx.
                serverIdx = protoIdx + 1;
            }


            var thisConfig = new List<string>(configClean);
            thisConfig.Insert(serverIdx, string.Format("remote {0} {1}", hostname, port));
            return string.Join("\r\n", thisConfig.ToArray());
        }
    }
}
