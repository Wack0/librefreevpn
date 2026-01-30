using IniParser.Parser;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace LibFreeVPN.Servers
{
    public sealed class V2RayServerSurge : VPNServerBase<V2RayServerSurge, V2RayServerSurge.Parser>
    {

        public sealed class Parser : VPNServerConfigParserFullBase<V2RayServerSurge>
        {
            public override V2RayServerSurge CreateInstance(string config)
                => new V2RayServerSurge(config);

            public override V2RayServerSurge CreateInstance(string config, string hostname, string port)
                => new V2RayServerSurge(config, hostname, port);

            public override V2RayServerSurge CreateInstance(string config, IReadOnlyDictionary<string, string> extraRegistry)
                => new V2RayServerSurge(config, extraRegistry);

            public override V2RayServerSurge CreateInstance(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry)
                => new V2RayServerSurge(config, hostname, port, extraRegistry);

            public override V2RayServerSurge CreateInstance(string hostname, string port)
            {
                throw new NotSupportedException();
            }

            public override V2RayServerSurge CreateInstance(string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry)
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
            }

            public override IEnumerable<(string config, string hostname, string port)> ParseConfigFull(string config)
            {
                var iniData = s_IniParser.Parse(config);

                var splitData = iniData["Proxy"]
                    .Where((data) => data.Value.Contains(','))
                    .Select((data) =>
                    {
                        var value = data.Value.Split(',');
                        // protocol,hostname,port,kv1,kv2,kv3...
                        // protocol://base64-json-config
                        for (int i = 0; i < value.Length; i++) value[i] = value[i].Trim();
                        return value;
                    });


                // TODO: handle other protocols here where relevant
                // known other protocols to exist: ss (shadowsocks?), trojan

                var vmessData = splitData.Where((value) => value[0].ToLower() == "vmess")
                    .Select((value) =>
                    {
                        var dict = new Dictionary<string, string>()
                        {
                            { "hostname", value[1] },
                            { "port", value[2] }
                        };
                        for (int i = 3; i < value.Length; i++)
                        {
                            var kv = value[i].Split(s_SplitKv, 2);
                            kv[0] = kv[0].Trim();
                            kv[1] = kv[1].Trim();

                            dict.Add(kv[0], kv[1]);
                        }

                        return dict;
                    })
                    .Where((dict) => dict.ContainsKey("username"))
                    .Select((dict) =>
                    {
                        // BUGBUG: probably needs more work when more surge configs are found
                        var hostname = dict["hostname"];
                        var port = dict["port"];

                        var jsonConfig = new JsonObject()
                        {
                            ["v"] = "2",
                            ["ps"] = string.Format("{0}:{1}", hostname, port),
                            ["add"] = hostname,
                            ["port"] = port,
                            ["id"] = dict["username"],
                            ["aid"] = "0",
                            ["net"] = dict.GetValue("ws").ToLower() == "true" ? "ws" : "tcp",
                            ["scy"] = "auto",
                            ["type"] = "none",
                            ["host"] = dict.GetValue("ws-host"),
                            ["path"] = dict.GetValue("ws-path"),
                            ["tls"] = dict.GetValue("tls").ToLower() == "true" ? "tls" : "",
                            ["sni"] = dict.GetValue("sni"),
                            ["alpn"] = ""
                        };

                        var thisConfig = string.Format("vmess://{0}", Convert.ToBase64String(Encoding.UTF8.GetBytes(jsonConfig.ToJsonString())));
                        var ws_host = dict.GetValue("ws-host");
                        if (!string.IsNullOrEmpty(ws_host) && ws_host != hostname) hostname = string.Empty;
                        return (thisConfig, hostname, port);
                    });

                return vmessData;
            }

            public override void AddExtraProperties(IDictionary<string, string> registry, string config)
            {
                registry.Add(ServerRegistryKeys.OriginalConfigType, "surge");
                registry.Add(ServerRegistryKeys.OriginalConfig, config);
            }
        }

        public override ServerProtocol Protocol => ServerProtocol.V2Ray;


        public V2RayServerSurge(string config) : base(config)
        {
        }

        public V2RayServerSurge(string config, string hostname, string port) : base(config, hostname, port)
        {
        }

        public V2RayServerSurge(string config, IReadOnlyDictionary<string, string> extraRegistry) : base(config, extraRegistry)
        {
        }

        public V2RayServerSurge(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry) : base(config, hostname, port, extraRegistry)
        {
        }
    }
}
