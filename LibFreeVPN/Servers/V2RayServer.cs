using LibFreeVPN.Servers.V2Ray;
using System;
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
    // v2ray parser (fro regular json config)
    public sealed class V2RayServer : VPNServerBase<V2RayServer, V2RayServer.Parser>
    {
        public sealed class Parser : VPNServerConfigParserFullBase<V2RayServer>
        {
            public override bool CanCreateInstance(bool withConfig) => withConfig;

            public override V2RayServer CreateInstance(string config)
                => new V2RayServer(config);

            public override V2RayServer CreateInstance(string config, string hostname, string port)
                => new V2RayServer(config, hostname, port);

            public override V2RayServer CreateInstance(string config, IReadOnlyDictionary<string, string> extraRegistry)
                => new V2RayServer(config, extraRegistry);

            public override V2RayServer CreateInstance(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry)
                => new V2RayServer(config, hostname, port, extraRegistry);

            public override V2RayServer CreateInstance(string hostname, string port)
            {
                throw new NotImplementedException();
            }

            public override V2RayServer CreateInstance(string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry)
            {
                throw new NotImplementedException();
            }

            public override IEnumerable<(string config, string hostname, string port)> ParseConfigFull(string config)
            {
                if (config.StartsWith("vless://"))
                {
                    var parsed = new Uri(config.Trim());
                    return (config.Trim(), parsed.Host, parsed.Port.ToString()).EnumerableSingle();
                }
                var json = JsonDocument.Parse(config);
                if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                if (!json.RootElement.TryGetProperty("outbounds", out var serversElem)) throw new InvalidDataException();
                if (serversElem.ValueKind != JsonValueKind.Array) throw new InvalidDataException();


                json.RootElement.TryGetPropertyString("remarks", out var remarks);
                var outbounds = serversElem.Deserialize<List<Outbounds4Ray>>();
                var outboundsSbox = serversElem.Deserialize<List<Outbound4Sbox>>();

                // TODO: support other protocols

                var vmessData = outbounds.Where((elem) => elem.protocol == "vmess").SelectMany((elem) =>
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
                    var server = elem.settings.vnext[0];
                    var user = server.users[0];

                    var jsonConfig = new JsonObject()
                    {
                        ["v"] = "2"
                    };

                    if (!string.IsNullOrEmpty(remarks)) jsonConfig.Add("ps", remarks);

                    var host = server.address;
                    if (IPAddress.TryParse(host, out var ipAddr) && ipAddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        if (host[0] != '[' || host.Last() != ']') host = "[" + host + "]";
                    }
                    jsonConfig.Add("add", host);
                    jsonConfig.Add("port", server.port.ToString());
                    jsonConfig.Add("id", user.id);
                    jsonConfig.Add("aid", user.alterId.HasValue ? user.alterId.Value.ToString() : "0");
                    jsonConfig.Add("scy", user.security);

                    switch (elem.streamSettings.security)
                    {
                        case "tls":
                            jsonConfig.AddNonNullValue("tls", elem.streamSettings.security);
                            if (elem.streamSettings.tlsSettings.alpn != null && elem.streamSettings.tlsSettings.alpn.Count > 0)
                                jsonConfig.Add("alpn", string.Join(",", elem.streamSettings.tlsSettings.alpn));
                            jsonConfig.AddNonNullValue("fp", elem.streamSettings.tlsSettings.fingerprint);
                            jsonConfig.AddNonNullValue("sni", elem.streamSettings.tlsSettings.serverName);
                            break;
                    }

                    var net = elem.streamSettings.network;
                    if (string.IsNullOrEmpty(net)) net = "tcp";
                    if (net == "h2") net = "http";
                    jsonConfig.Add("net", net);

                    switch (net)
                    {
                        case "tcp":
                            jsonConfig.Add("type", elem.streamSettings.tcpSettings?.header?.type ?? "none");
                            jsonConfig.AddNonNullValue("host", elem.streamSettings.tcpSettings?.header?.request?.headers?["Host"]?.FirstOrDefault());
                            break;
                        case "kcp":
                            jsonConfig.Add("type", elem.streamSettings.kcpSettings?.header?.type ?? "none");
                            jsonConfig.AddNonNullValue("path", elem.streamSettings.kcpSettings?.seed);
                            break;
                        case "ws":
                            if (string.IsNullOrEmpty(elem.streamSettings.wsSettings?.host)) jsonConfig.AddNonNullValue("host", elem.streamSettings.wsSettings?.headers?.Host);
                            else jsonConfig.AddNonNullValue("host", elem.streamSettings.wsSettings?.host);
                            jsonConfig.AddNonNullValue("path", elem.streamSettings.wsSettings?.path);
                            break;
                        case "httpUpgrade":
                            jsonConfig.AddNonNullValue("host", elem.streamSettings.httpupgradeSettings?.host);
                            jsonConfig.AddNonNullValue("path", elem.streamSettings.httpupgradeSettings?.path);
                            break;
                        case "xhttp":
                            jsonConfig.AddNonNullValue("host", elem.streamSettings.xhttpSettings?.host);
                            jsonConfig.AddNonNullValue("path", elem.streamSettings.xhttpSettings?.path);
                            jsonConfig.AddNonNullValue("type", elem.streamSettings.xhttpSettings?.mode);
                            break;
                        case "http":
                            jsonConfig.AddNonNullValue("host", elem.streamSettings.httpSettings?.host?.FirstOrDefault());
                            jsonConfig.AddNonNullValue("path", elem.streamSettings.httpSettings?.path);
                            break;
                        case "quic":
                            jsonConfig.Add("type", elem.streamSettings.quicSettings?.header?.type ?? "none");
                            jsonConfig.AddNonNullValue("host", elem.streamSettings.quicSettings?.security);
                            jsonConfig.AddNonNullValue("path", elem.streamSettings.quicSettings?.key);
                            break;
                        case "grpc":
                            jsonConfig.AddNonNullValue("host", elem.streamSettings.grpcSettings?.authority);
                            jsonConfig.AddNonNullValue("path", elem.streamSettings.grpcSettings?.serviceName);
                            if (elem.streamSettings.grpcSettings?.multiMode == true) jsonConfig.Add("type", "multi");
                            break;
                    }

                    var thisConfig = string.Format("vmess://{0}", Convert.ToBase64String(Encoding.UTF8.GetBytes(jsonConfig.ToJsonString())));
                    return (thisConfig, host, server.port.ToString());
                });

                var vlessData = outbounds.Where((elem) => elem.protocol == "vless").SelectMany((elem) =>
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
                    var server = elem.settings.vnext[0];
                    var user = server.users[0];

                    var query = System.Web.HttpUtility.ParseQueryString(string.Empty);
                    query.Add("encryption", user.encryption ?? "none");
                    query.AddNonNullValue("flow", user.flow);
                    switch (elem.streamSettings.security)
                    {
                        case "tls":
                            query.AddNonNullValue("security", elem.streamSettings.security);
                            if (elem.streamSettings.tlsSettings.allowInsecure == true) query.Add("allowInsecure", "1");
                            if (elem.streamSettings.tlsSettings.alpn != null && elem.streamSettings.tlsSettings.alpn.Count > 0)
                                query.Add("alpn", string.Join(",", elem.streamSettings.tlsSettings.alpn));
                            query.AddNonNullValue("fp", elem.streamSettings.tlsSettings.fingerprint);
                            query.AddNonNullValue("sni", elem.streamSettings.tlsSettings.serverName);
                            break;
                        case "reality":
                            query.AddNonNullValue("security", elem.streamSettings.security);
                            query.AddNonNullValue("fp", elem.streamSettings.realitySettings.fingerprint);
                            query.AddNonNullValue("sni", elem.streamSettings.realitySettings.serverName);
                            query.AddNonNullValue("pbk", elem.streamSettings.realitySettings.publicKey);
                            query.AddNonNullValue("sid", elem.streamSettings.realitySettings.shortId);
                            query.AddNonNullValue("spx", elem.streamSettings.realitySettings.spiderX);
                            break;
                    }

                    var net = elem.streamSettings.network;
                    if (string.IsNullOrEmpty(net)) net = "tcp";
                    if (net == "h2") net = "http";
                    query.Add("type", net);

                    switch (net)
                    {
                        case "tcp":
                            query.Add("headerType", elem.streamSettings.tcpSettings?.header?.type ?? "none");
                            query.AddNonNullValue("host", elem.streamSettings.tcpSettings?.header?.request?.headers?["Host"]?.FirstOrDefault());
                            break;
                        case "kcp":
                            query.Add("headerType", elem.streamSettings.kcpSettings?.header?.type ?? "none");
                            query.AddNonNullValue("seed", elem.streamSettings.kcpSettings?.seed);
                            break;
                        case "ws":
                            if (string.IsNullOrEmpty(elem.streamSettings.wsSettings?.host)) query.AddNonNullValue("host", elem.streamSettings.wsSettings?.headers?.Host);
                            else query.AddNonNullValue("host", elem.streamSettings.wsSettings?.host);
                            query.AddNonNullValue("path", elem.streamSettings.wsSettings?.path);
                            break;
                        case "httpUpgrade":
                            query.AddNonNullValue("host", elem.streamSettings.httpupgradeSettings?.host);
                            query.AddNonNullValue("path", elem.streamSettings.httpupgradeSettings?.path);
                            break;
                        case "xhttp":
                            query.AddNonNullValue("host", elem.streamSettings.xhttpSettings?.host);
                            query.AddNonNullValue("path", elem.streamSettings.xhttpSettings?.path);
                            query.AddNonNullValue("mode", elem.streamSettings.xhttpSettings?.mode);
                            var extra = elem.streamSettings.xhttpSettings?.extra;
                            if (extra != null) query.Add("extra", JsonSerializer.Serialize(extra));
                            break;
                        case "http":
                            query.AddNonNullValue("host", elem.streamSettings.httpSettings?.host?.FirstOrDefault());
                            query.AddNonNullValue("path", elem.streamSettings.httpSettings?.path);
                            break;
                        case "quic":
                            query.Add("headerType", elem.streamSettings.quicSettings?.header?.type ?? "none");
                            query.AddNonNullValue("quicSecurity", elem.streamSettings.quicSettings?.security);
                            query.AddNonNullValue("key", elem.streamSettings.quicSettings?.key);
                            break;
                        case "grpc":
                            query.AddNonNullValue("authority", elem.streamSettings.grpcSettings?.authority);
                            query.AddNonNullValue("serviceName", elem.streamSettings.grpcSettings?.serviceName);
                            if (elem.streamSettings.grpcSettings?.multiMode == true) query.Add("mode", "multi");
                            break;
                    }

                    var ub = new UriBuilder();
                    ub.Scheme = "vless";
                    ub.UserName = user.id;
                    ub.Host = server.address;
                    if (IPAddress.TryParse(ub.Host, out var ipAddr) && ipAddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        if (ub.Host[0] != '[' || ub.Host.Last() != ']') ub.Host = "[" + ub.Host + "]";
                    }
                    ub.Port = server.port;
                    ub.Query = query.ToString();
                    if (!string.IsNullOrEmpty(remarks)) ub.Fragment = remarks;

                    return (ub.Uri.ToString(), ub.Host, ub.Port.ToString());
                });
                var vlessSboxData = outboundsSbox.Where((elem) => elem.type == "vless").Select((elem) =>
                {
                    var server = elem;
                    var user = server;

                    var query = System.Web.HttpUtility.ParseQueryString(string.Empty);
                    var security = "none";
                    if (elem.tls != null)
                    {
                        if (elem.tls?.reality?.enabled == true) security = "reality";
                        else security = "tls";
                    }
                    query.Add("encryption", "none");
                    query.AddNonNullValue("flow", user.flow);
                    switch (security)
                    {
                        case "tls":
                            query.AddNonNullValue("security", security);
                            if (elem.tls?.insecure == true) query.Add("allowInsecure", "1");
                            if (elem.tls.alpn != null && elem.tls.alpn.Count > 0)
                                query.Add("alpn", string.Join(",", elem.tls.alpn));
                            if (elem.tls?.utls?.enabled == true) query.AddNonNullValue("fp", elem.tls?.utls?.fingerprint);
                            query.AddNonNullValue("sni", elem.tls?.server_name);
                            break;
                        case "reality":
                            query.AddNonNullValue("security", security);
                            query.AddNonNullValue("fp", elem.tls?.utls?.fingerprint);
                            query.AddNonNullValue("sni", elem.tls?.server_name);
                            query.AddNonNullValue("pbk", elem.tls?.reality?.public_key);
                            query.AddNonNullValue("sid", elem.tls?.reality?.short_id);
                            break;
                    }

                    var net = elem.transport?.type;
                    if (string.IsNullOrEmpty(net)) net = "tcp";
                    if (net == "h2") net = "http";
                    query.Add("type", net);

                    switch (net)
                    {
                        case "tcp":
                            query.Add("headerType", elem.transport?.type ?? "none");
                            query.AddNonNullValue("host", elem.transport?.hostList?.FirstOrDefault());
                            query.AddNonNullValue("path", elem.transport?.path);
                            break;
                        case "ws":
                            query.AddNonNullValue("host", elem.transport?.headers?.Host);
                            query.AddNonNullValue("path", elem.transport?.path);
                            break;
                        case "httpupgrade":
                            query.AddNonNullValue("host", elem.transport?.hostString);
                            query.AddNonNullValue("path", elem.transport?.path);
                            break;
                        case "http":
                            query.AddNonNullValue("host", elem.transport?.hostList?.FirstOrDefault());
                            query.AddNonNullValue("path", elem.transport?.path);
                            break;
                        case "quic":
                            break;
                        case "grpc":
                            query.AddNonNullValue("serviceName", elem.transport?.path);
                            break;
                    }

                    var ub = new UriBuilder();
                    ub.Scheme = "vless";
                    ub.UserName = user.uuid;
                    ub.Host = server.server;
                    if (IPAddress.TryParse(ub.Host, out var ipAddr) && ipAddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        if (ub.Host[0] != '[' || ub.Host.Last() != ']') ub.Host = "[" + ub.Host + "]";
                    }
                    ub.Port = server.server_port.Value;
                    ub.Query = query.ToString();
                    if (!string.IsNullOrEmpty(remarks)) ub.Fragment = remarks;

                    return (ub.Uri.ToString(), ub.Host, ub.Port.ToString());
                });

                return vlessData.Concat(vmessData).Concat(vlessSboxData);
            }

            public override void AddExtraProperties(IDictionary<string, string> registry, string config)
            {
                if (config.StartsWith("vless://"))
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

        public override ServerProtocol Protocol => ServerProtocol.V2Ray;


        public V2RayServer(string config) : base(config)
        {
        }

        public V2RayServer(string config, string hostname, string port) : base(config, hostname, port)
        {
        }

        public V2RayServer(string config, IReadOnlyDictionary<string, string> extraRegistry) : base(config, extraRegistry)
        {
        }

        public V2RayServer(string config, string hostname, string port, IReadOnlyDictionary<string, string> extraRegistry) : base(config, hostname, port, extraRegistry)
        {
        }
    }
}
