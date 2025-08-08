using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using static LibFreeVPN.Servers.V2RayServer.Parser;

// JSON object defs for the v2ray conf part that we care about:

namespace LibFreeVPN.Servers.V2Ray
{
    public class Outbounds4Ray
    {
        public string tag { get; set; }

        public string protocol { get; set; }

        public Outboundsettings4Ray settings { get; set; }

        public StreamSettings4Ray streamSettings { get; set; }

        public Mux4Ray mux { get; set; }
    }

    public class UsersItem4Ray
    {
        public string id { get; set; }

        public int? alterId { get; set; }

        public string email { get; set; }

        public string security { get; set; }

        public string encryption { get; set; }

        public string flow { get; set; }
    }

    public class Outboundsettings4Ray
    {
        public List<VnextItem4Ray> vnext { get; set; }

        public List<ServersItem4Ray> servers { get; set; }

        public Response4Ray response { get; set; }

        public string domainStrategy { get; set; }

        public int? userLevel { get; set; }

        public FragmentItem4Ray fragment { get; set; }

        public string secretKey { get; set; }

        public List<string> address { get; set; }

        public List<WireguardPeer4Ray> peers { get; set; }

        public bool? noKernelTun { get; set; }

        public int? mtu { get; set; }

        public List<int> reserved { get; set; }

        public int? workers { get; set; }
    }

    public class WireguardPeer4Ray
    {
        public string endpoint { get; set; }
        public string publicKey { get; set; }
    }

    public class VnextItem4Ray
    {
        public string address { get; set; }

        public int port { get; set; }

        public List<UsersItem4Ray> users { get; set; }
    }

    public class ServersItem4Ray
    {
        public string email { get; set; }

        public string address { get; set; }

        public string method { get; set; }

        public bool? ota { get; set; }

        public string password { get; set; }

        public int port { get; set; }

        public int? level { get; set; }

        public string flow { get; set; }

        public List<SocksUsersItem4Ray> users { get; set; }
    }

    public class SocksUsersItem4Ray
    {
        public string user { get; set; }

        public string pass { get; set; }

        public int? level { get; set; }
    }

    public class Mux4Ray
    {
        public bool enabled { get; set; }
        public int? concurrency { get; set; }
        public int? xudpConcurrency { get; set; }
        public string xudpProxyUDP443 { get; set; }
    }

    public class Response4Ray
    {
        public string type { get; set; }
    }

    public class StreamSettings4Ray
    {
        public string network { get; set; }

        public string security { get; set; }

        public TlsSettings4Ray tlsSettings { get; set; }

        public TcpSettings4Ray tcpSettings { get; set; }

        public KcpSettings4Ray kcpSettings { get; set; }

        public WsSettings4Ray wsSettings { get; set; }

        public HttpupgradeSettings4Ray httpupgradeSettings { get; set; }

        public XhttpSettings4Ray xhttpSettings { get; set; }

        public HttpSettings4Ray httpSettings { get; set; }

        public QuicSettings4Ray quicSettings { get; set; }

        public TlsSettings4Ray realitySettings { get; set; }

        public GrpcSettings4Ray grpcSettings { get; set; }

        public Sockopt4Ray sockopt { get; set; }
    }

    public class TlsSettings4Ray
    {
        public bool? allowInsecure { get; set; }

        public string serverName { get; set; }

        public List<string> alpn { get; set; }

        public string fingerprint { get; set; }

        public bool? show { get; set; }
        public string publicKey { get; set; }
        public string shortId { get; set; }
        public string spiderX { get; set; }
    }

    public class TcpSettings4Ray
    {
        public Header4Ray header { get; set; }
    }

    public class Header4Ray
    {
        public string type { get; set; }

        public HttpRequest4Ray request { get; set; }

        public HttpResponse4Ray response { get; set; }

        public string domain { get; set; }
    }

    public class KcpSettings4Ray
    {
        public int mtu { get; set; }

        public int tti { get; set; }

        public int uplinkCapacity { get; set; }

        public int downlinkCapacity { get; set; }

        public bool congestion { get; set; }

        public int readBufferSize { get; set; }

        public int writeBufferSize { get; set; }

        public Header4Ray header { get; set; }

        public string seed { get; set; }
    }

    public class WsSettings4Ray
    {
        public string path { get; set; }
        public string host { get; set; }

        public Headers4Ray headers { get; set; }
    }

    public class Headers4Ray
    {
        public string Host { get; set; }

        [JsonPropertyName("User-Agent")]
        public string UserAgent { get; set; }
    }

    public class HttpupgradeSettings4Ray
    {
        public string path { get; set; }

        public string host { get; set; }
    }

    public class XhttpSettings4Ray
    {
        public string path { get; set; }
        public string host { get; set; }
        public string mode { get; set; }
        public object extra { get; set; }
    }

    public class HttpSettings4Ray
    {
        public string path { get; set; }

        public List<string> host { get; set; }
    }

    public class QuicSettings4Ray
    {
        public string security { get; set; }

        public string key { get; set; }

        public Header4Ray header { get; set; }
    }

    public class GrpcSettings4Ray
    {
        public string authority { get; set; }
        public string serviceName { get; set; }
        public bool multiMode { get; set; }
        public int? idle_timeout { get; set; }
        public int? health_check_timeout { get; set; }
        public bool? permit_without_stream { get; set; }
        public int? initial_windows_size { get; set; }
    }

    public class Sockopt4Ray
    {
        public string dialerProxy { get; set; }
    }

    public class FragmentItem4Ray
    {
        public string packets { get; set; }
        public string length { get; set; }
        public string interval { get; set; }
    }

    public class HttpRequest4Ray
    {
        public string version { get; set; }
        public string method { get; set; }
        public List<string> path { get; set; }
        public Dictionary<string, List<string>> headers { get; set; }
    }

    public class HttpResponse4Ray
    {
        public string version { get; set; }
        public string status { get; set; }
        public string reason { get; set; }
        public Dictionary<string, List<string>> headers { get; set; }
    }

    /*
"xhttpSettings": {
    "host": "example.com",
    "path": "/yourpath", // must be the same
    "mode": "auto",
    "extra": {
        "headers": {
            // "key": "value"
        },
        "xPaddingBytes": "100-1000",
        "noGRPCHeader": false, // stream-up/one, client only
        "noSSEHeader": false, // server only
        "scMaxEachPostBytes": 1000000, // packet-up only
        "scMinPostsIntervalMs": 30, // packet-up, client only
        "scMaxBufferedPosts": 30, // packet-up, server only
        "scStreamUpServerSecs": "20-80", // stream-up, server only
        "xmux": { // h2/h3 mainly, client only
            "maxConcurrency": "16-32",
            "maxConnections": 0,
            "cMaxReuseTimes": 0,
            "hMaxRequestTimes": "600-900",
            "hMaxReusableSecs": "1800-3000",
            "hKeepAlivePeriod": 0
        },
        "downloadSettings": { // client only
            "address": "", // another domain/IP
            "port": 443,
            "network": "xhttp", // must be "xhttp"
            "security": "tls", // or "reality"
            "tlsSettings": {
                // ...
            },
            "xhttpSettings": {
                "path": "/yourpath", // must be the same
                // ... other XHTTP params specific to download if needed
            },
            "sockopt": {} // will be replaced by upload's "sockopt" if the latter's "penetrate" is true
        }
    }
}
    */

    public class XhttpExtra4Ray
    {
        public Dictionary<string, string> headers { get; set; }

        public string xPaddingBytes { get; set; }

        public bool? noGRPCHeader { get; set; }

        public bool? noSSEHeader { get; set; }

        public int? scMaxEachPostBytes { get; set; }

        public int? scMinPostsIntervalMs { get; set; }
        public int? scMaxBufferedPosts { get; set; }

        public string scStreamUpServerSecs { get; set; }

        public XhttpXmux4Ray xmux { get; set; }

        public XhttpDownloadSettings4Ray downloadSettings { get; set; }
    }

    public class XhttpXmux4Ray
    {
        public string maxConcurrency { get; set; }
        public int? maxConnections { get; set; }

        public int? cMaxReuseTimes { get; set; }

        public string hMaxRequestTimes { get; set; }

        public string hMaxReusableSecs { get; set; }

        public int? hKeepAlivePeriod { get; set; }
    }

    public class XhttpDownloadSettings4Ray
    {
        public string address { get; set; }
        public int? port { get; set; }
        public string network { get; set; }
        public string security { get; set; }
        public TlsSettings4Ray tlsSettings { get; set; }
        public XhttpSettings4Ray xhttpSettings { get; set; }
        public Sockopt4Ray sockopt { get; set; }
    }

    public class Outbound4Sbox
    {
        public string type { get; set; }
        public string tag { get; set; }
        public string server { get; set; }
        public int? server_port { get; set; }
        public List<string> server_ports { get; set; }
        public string uuid { get; set; }
        public string security { get; set; }
        public int? alter_id { get; set; }
        public string flow { get; set; }
        public string hop_interval { get; set; }
        public int? up_mbps { get; set; }
        public int? down_mbps { get; set; }
        public string auth_str { get; set; }
        public int? recv_window_conn { get; set; }
        public int? recv_window { get; set; }
        public bool? disable_mtu_discovery { get; set; }
        public string detour { get; set; }
        public string method { get; set; }
        public string username { get; set; }
        public string password { get; set; }
        public string congestion_control { get; set; }
        public string version { get; set; }
        public string network { get; set; }
        public string packet_encoding { get; set; }
        public List<string> local_address { get; set; }
        public string private_key { get; set; }
        public string peer_public_key { get; set; }
        public List<int> reserved { get; set; }
        public int? mtu { get; set; }
        public string plugin { get; set; }
        public string plugin_opts { get; set; }
        public Tls4Sbox tls { get; set; }
        public Multiplex4Sbox multiplex { get; set; }
        public Transport4Sbox transport { get; set; }
        public HyObfs4Sbox obfs { get; set; }
        public List<string> outbounds { get; set; }
        public bool? interrupt_exist_connections { get; set; }
    }

    public class Tls4Sbox
    {
        public bool enabled { get; set; }
        public string server_name { get; set; }
        public bool? insecure { get; set; }
        public List<string> alpn { get; set; }
        public Utls4Sbox utls { get; set; }
        public Reality4Sbox reality { get; set; }
    }

    public class Multiplex4Sbox
    {
        public bool enabled { get; set; }
        public string protocol { get; set; }
        public int max_connections { get; set; }
        public bool? padding { get; set; }
    }

    public class Utls4Sbox
    {
        public bool enabled { get; set; }
        public string fingerprint { get; set; }
    }

    public class Reality4Sbox
    {
        public bool enabled { get; set; }
        public string public_key { get; set; }
        public string short_id { get; set; }
    }

    public class Transport4Sbox
    {
        public string type { get; set; }

        [JsonPropertyName("host")]
        public JsonElement? host { get; set; }
        public string path { get; set; }
        public Headers4Sbox headers { get; set; }

        public string service_name { get; set; }
        public string idle_timeout { get; set; }
        public string ping_timeout { get; set; }
        public bool? permit_without_stream { get; set; }

        [JsonIgnore]
        public string hostString
        {
            get
            {
                if (host?.ValueKind == JsonValueKind.String)
                {
                    return host?.ToString();
                }

                return null;
            }
        }

        [JsonIgnore]
        public List<string> hostList
        {
            get
            {
                if (host?.ValueKind == JsonValueKind.Array)
                {
                    try
                    {
                        return host?.Deserialize<List<string>>();
                    }
                    catch
                    {
                        return null;
                    }
                }

                return null;
            }
        }
    }

    public class Headers4Sbox
    {
        public string Host { get; set; }
    }

    public class HyObfs4Sbox
    {
        public string type { get; set; }
        public string password { get; set; }
    }
}
