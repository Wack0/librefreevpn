using LibFreeVPN.Servers.V2Ray;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace LibFreeVPN.Servers
{
    // web proxy server parser, parses v2ray style URIs, curl proxy style URIs, and v2ray configs
    public sealed class WebProxyServer : VPNServerBase<WebProxyServer, WebProxyServer.Parser>
    {
        public sealed class Parser : VPNServerConfigParserFullBase<WebProxyServer>
        {
            public override bool CanCreateInstance(bool withConfig) => withConfig;

            public override WebProxyServer CreateInstance(string config)
                => new WebProxyServer(config);

            public override WebProxyServer CreateInstance(string config, string hostname, string port)
                => new WebProxyServer(config, hostname, port);

            public override WebProxyServer CreateInstance(string config, IReadOnlyDictionary<string, string> extraRegistry)
                => new WebProxyServer(config, extraRegistry);

            public override WebProxyServer CreateInstance(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry)
                => new WebProxyServer(config, hostname, port, extraRegistry);

            public override WebProxyServer CreateInstance(string hostname, string port)
            {
                throw new NotImplementedException();
            }

            public override WebProxyServer CreateInstance(string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry)
            {
                throw new NotImplementedException();
            }

            private static readonly char[] s_SplitAuth = new char[] { ':' };

            public override IEnumerable<(string config, string hostname, string port)> ParseConfigFull(string config)
            {
                if (config.StartsWith("http://") || config.StartsWith("https://"))
                {
                    var parsed = new Uri(config.Trim());
                    return (config.Trim(), parsed.Host, parsed.Port.ToString()).EnumerableSingle();
                }
                if (config.StartsWith("socks5h://"))
                {
                    var parsed = new Uri(config.Trim());
                    var ub = new UriBuilder();
                    ub.Scheme = "socks";
                    ub.Host = parsed.Host;
                    ub.Port = parsed.Port;
                    ub.UserName = Convert.ToBase64String(Encoding.ASCII.GetBytes(parsed.UserInfo));
                    var lines = string.Join("\r\n", new string[]
                    {
                        config.Trim(),
                        ub.ToString()
                    });
                    return (lines, parsed.Host, parsed.Port.ToString()).EnumerableSingle();
                }
                if (config.StartsWith("socks://"))
                {
                    var parsed = new Uri(config.Trim());
                    var ub = new UriBuilder();
                    ub.Scheme = "socks5h";
                    ub.Host = parsed.Host;
                    ub.Port = parsed.Port;
                    var auth = Encoding.ASCII.FromBase64String(parsed.UserInfo).Split(s_SplitAuth, 2);
                    ub.UserName = auth[0];
                    ub.Password = auth[1];
                    var lines = string.Join("\r\n", new string[]
                    {
                        ub.ToString(),
                        config.Trim(),
                    });
                    return (lines, parsed.Host, parsed.Port.ToString()).EnumerableSingle();
                }


                var json = JsonDocument.Parse(config);
                if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                if (!json.RootElement.TryGetProperty("outbounds", out var serversElem)) throw new InvalidDataException();
                if (serversElem.ValueKind != JsonValueKind.Array) throw new InvalidDataException();


                json.RootElement.TryGetPropertyString("remarks", out var remarks);
                var outbounds = serversElem.Deserialize<List<Outbounds4Ray>>();
                var outboundsSbox = serversElem.Deserialize<List<Outbound4Sbox>>();

                var httpData = outbounds.Where((elem) => elem.protocol == "http").SelectMany((elem) =>
                {
                    // Convert one outbound with several servers to several outbounds with one server each.
                    var servers = elem.settings.vnext;

                    var list = new List<Outbounds4Ray>();
                    foreach (var server in servers)
                    {
                        // Convert one server with several users to several servers with one user each.
                        var users = server.users;
                        foreach (var user in users)
                        {
                            server.users = new List<UsersItem4Ray>() { user };
                            elem.settings.vnext = new List<VnextItem4Ray>() { server };
                            list.Add(elem);
                        }
                    }

                    return list;
                }).Select((elem) =>
                {
                    var server = elem.settings.servers[0];
                    var ub = new UriBuilder();
                    ub.Scheme = "http";
                    if (server.users.Count != 0)
                    {
                        ub.UserName = server.users[0].user;
                        ub.Password = server.users[0].pass;
                    }
                    ub.Host = server.address;
                    ub.Port = server.port;

                    return (ub.Uri.ToString(), ub.Host, ub.Port.ToString());
                });

                var socksData = outbounds.Where((elem) => elem.protocol == "socks").SelectMany((elem) =>
                {
                    // Convert one outbound with several servers to several outbounds with one server each.
                    var servers = elem.settings.vnext;

                    var list = new List<Outbounds4Ray>();
                    foreach (var server in servers)
                    {
                        // Convert one server with several users to several servers with one user each.
                        var users = server.users;
                        foreach (var user in users)
                        {
                            server.users = new List<UsersItem4Ray>() { user };
                            elem.settings.vnext = new List<VnextItem4Ray>() { server };
                            list.Add(elem);
                        }
                    }

                    return list;
                }).Select((elem) =>
                {
                    var server = elem.settings.servers[0];
                    var ub = new UriBuilder();
                    var ub2 = new UriBuilder();
                    ub.Scheme = "socks5h";
                    ub2.Scheme = "socks";
                    if (server.users.Count != 0)
                    {
                        ub.UserName = server.users[0].user;
                        ub.Password = server.users[0].pass;
                        ub.UserName = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", server.users[0].user, server.users[0].pass)));
                    }
                    ub.Host = server.address;
                    ub2.Host = server.address;
                    ub.Port = server.port;
                    ub2.Port = server.port;


                    var lines = string.Join("\r\n", new string[]
                    {
                        ub.ToString(),
                        ub2.ToString()
                    });
                    return (lines, ub.Host, ub.Port.ToString());
                });

                return httpData.Concat(socksData);
            }

            public override void AddExtraProperties(IDictionary<string, string> registry, string config)
            {
                if (config.StartsWith("http://") || config.StartsWith("https://") || config.StartsWith("socks5h://")) return;

                if (config.StartsWith("socks://"))
                {
                    if (!registry.ContainsKey(ServerRegistryKeys.DisplayName))
                    {
                        var parsed = new Uri(config.Trim());
                        registry.Add(ServerRegistryKeys.DisplayName, parsed.Fragment);
                    }
                    return;
                }

                registry.Add(ServerRegistryKeys.OriginalConfigType, "v2ray");

                // For the original config, grab the outbounds elem and provide that entire array.
                var configJson = JsonDocument.Parse(config);

                if (configJson.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                if (!configJson.RootElement.TryGetProperty("outbounds", out var serversElem)) throw new InvalidDataException();
                if (serversElem.ValueKind != JsonValueKind.Array) throw new InvalidDataException();

                var newArr = new JsonArray();
                foreach (var elem in serversElem.EnumerateArray()) newArr.Add(elem);
                var strippedConf = new JsonObject()
                {
                    ["outbounds"] = newArr
                };
                registry.Add(ServerRegistryKeys.OriginalConfig, strippedConf.ToString());
            }
        }

        public override ServerProtocol Protocol => ServerProtocol.WebProxy;


        public WebProxyServer(string config) : base(config)
        {
        }

        public WebProxyServer(string config, string hostname, string port) : base(config, hostname, port)
        {
        }

        public WebProxyServer(string config, IReadOnlyDictionary<string, string> extraRegistry) : base(config, extraRegistry)
        {
        }

        public WebProxyServer(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry) : base(config, hostname, port, extraRegistry)
        {
        }
    }
}
