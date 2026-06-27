using LibFreeVPN.ProviderHelpers;
using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace LibFreeVPN.Providers
{
    // Android app and electron app for Windows. OpenVPN, requires "device ID" to get creds but that can just be random data.
    // Also wireguard, but unable to get that working currently.
    public class OvpnArt : VPNProviderHttpGetBase
    {
        private static readonly string s_ServersUri = Encoding.ASCII.FromBase64String("aHR0cHM6Ly9zdGFydnBuLmNvbS9kYXNoYm9hcmQvbW9kdWxlcy9hZGRvbnMvd2htY3NhcGltb2R1bGUvdnBuX2hvc3RuYW1lc19mcmVlX2lwLnR4dA==");
        private static readonly string s_TemplateUriFormat = Encoding.ASCII.FromBase64String("aHR0cHM6Ly9maWxlcy5zdGFyaG9tZS5pby9kb3dubG9hZHMvb3Zwbi92cG4tYXBwLWZyZWUuezB9LnN0YXJ2cG4uY29tLm92cG4=");
        //private static readonly string s_TemplateWgUrl = Encoding.ASCII.FromBase64String("aHR0cHM6Ly9maWxlcy5zdGFyaG9tZS5pby9kb3dubG9hZHMvd2cvYXdnX2ZyZWV2cG5fc3RhcnZwbi5jb25m");
        private static readonly string s_CredsApiUri = Encoding.ASCII.FromBase64String("aHR0cHM6Ly9hcGkyLnN0YXJob21lLmlvLw==");
        private static readonly string s_CredsApiKey = Encoding.ASCII.FromBase64String("U1ZCbGllNWFrcXdvcEl6YmRrU1JiTFA4d0VpQnI1ZmZJbldDQkFBaU5iZDhySGdJOUNTTEM5d3FmbHJsMVQ3bw==");
        private static readonly string s_CredsApiDataFormat = Encoding.ASCII.FromBase64String("e3siY29tbWFuZCI6ImdldF9mcmVldnBuX3VzYWdlIiwiY3VzdG9tIjoxLCJkZXZpY2VpZCI6InswfSJ9fQ==");
        private static readonly string s_CredsKeyOvpnUsername = Encoding.ASCII.FromBase64String("dXNlcm5hbWVfb3BlbnZwbg==");
        private static readonly string s_CredsKeyOvpnPassword = Encoding.ASCII.FromBase64String("cGFzc3dvcmRfb3BlbnZwbg==");
        //private static readonly string s_CredsKeyWgPrivkey = Encoding.ASCII.FromBase64String("d2dwcml2YXRla2V5");
        //private static readonly string s_CredsKeyWgIpv4 = Encoding.ASCII.FromBase64String("YXdnaXB2NA==");
        //private static readonly string s_CredsKeyWgIpv6 = Encoding.ASCII.FromBase64String("YXdnaXB2Ng==");

        private static KeyValuePair<string, string> CreatePair(string key, string value)
        {
            if (value != string.Empty) value = Encoding.ASCII.FromBase64String(value);
            return new KeyValuePair<string, string>(Encoding.ASCII.FromBase64String(key), value);
        }

        private static readonly ReadOnlyCollection<KeyValuePair<string, string>> s_TemplateValuesOvpn = new List<KeyValuePair<string, string>>
        {
            CreatePair("e2Jsb2Nrb3V0c2lkZWRuc30=", string.Empty),
            CreatePair("e2RuczF9", "ZGhjcC1vcHRpb24gRE5TIDEuMS4xLjE="),
            CreatePair("e2RuczJ9", "ZGhjcC1vcHRpb24gRE5TIDEuMC4wLjE="),
            CreatePair("e2lmY29uZmlndjZ9", string.Empty),
            CreatePair("e3NlcnZlcnY2fQ==", string.Empty),
            CreatePair("e3R1bnY2fQ==", string.Empty),
            CreatePair("e3JvdXRldjZ9", string.Empty)
        }.AsReadOnly();

        private static readonly string s_TemplateKeyOvpnHostname = Encoding.ASCII.FromBase64String("e3JlbW90ZUhvc3R9");


        private static readonly string s_TemplateUriTcp = string.Format(s_TemplateUriFormat, "tcp");
        private static readonly string s_TemplateUriUdp = string.Format(s_TemplateUriFormat, "udp");

        private static readonly RNGCryptoServiceProvider s_Csprng = new RNGCryptoServiceProvider();


        public override string SampleSource => "aHR0cHM6Ly93d3cuc3RhcnZwbi5jb20vZG93bmxvYWRzL3dpbmFwcC9TdGFyVlBOLUZSMS14NjQtbGF0ZXN0LmV4ZQ==";

        public override string SampleVersion => "1.1.40";

        protected override string RequestUri => s_ServersUri;

        public override bool HasProtocol(ServerProtocol protocol)
            => protocol == ServerProtocol.OpenVPN;// || protocol == ServerProtocol.WireGuard;

        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl(string config)
        {
            // Download config templates.
            var TemplateTcp = new StringBuilder(await ServerUtilities.HttpClient.GetStringAsync(s_TemplateUriTcp));
            var TemplateUdp = new StringBuilder(await ServerUtilities.HttpClient.GetStringAsync(s_TemplateUriUdp));
            //string TemplateWg = await ServerUtilities.HttpClient.GetStringAsync(s_TemplateWgUrl);

            // Generate some random data.
            string randomData;
            {
                var randomBytes = new byte[0x10];
                s_Csprng.GetBytes(randomBytes);
                randomData = BitConverter.ToUInt64(randomBytes, 0).ToString("x16");
            }

            // TRADE OFFER:
            // i receive: vpn servers
            // you receive: lots of junk in your database of "unique device IDs for tracking"
            // Make the request twice, first request gives OpenVPN creds only, second request gives both OpenVPN and WireGuard.

            string credsResponse = null;

            //for (int i = 0; i < 2; i++)
            {
                using (var request = new HttpRequestMessage(HttpMethod.Post, s_CredsApiUri))
                {
                    request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(string.Format(s_CredsApiDataFormat, randomData)));
                    request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded");
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", s_CredsApiKey);
                    var post = await ServerUtilities.HttpClient.SendAsync(request);
                    credsResponse = await post.Content.ReadAsStringAsync();
                }
            }

            // Parse the response.
            var json = JsonDocument.Parse(credsResponse);
            if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            if (!json.RootElement.TryGetProperty("data", out var data)) throw new InvalidDataException();

            if (!data.TryGetPropertyString(s_CredsKeyOvpnUsername, out var ovpnUser)) throw new InvalidDataException();
            if (!data.TryGetPropertyString(s_CredsKeyOvpnPassword, out var ovpnPass)) throw new InvalidDataException();
            //if (!data.TryGetPropertyString(s_CredsKeyWgPrivkey, out var wgPrivkey)) throw new InvalidDataException();
            //if (!data.TryGetPropertyString(s_CredsKeyWgIpv4, out var wgIpv4)) throw new InvalidDataException();
            //if (!data.TryGetPropertyString(s_CredsKeyWgIpv6, out var wgIpv6)) throw new InvalidDataException();

            // Fill in the generic template values.
            foreach (var kvp in s_TemplateValuesOvpn)
            {
                TemplateTcp.Replace(kvp.Key, kvp.Value);
                TemplateUdp.Replace(kvp.Key, kvp.Value);
            }

            // Split the downloaded config (list of servers)
            var servers = config.Split(';').Select((server) => {
                var values = server.Trim().Split(',');
                for (int i = 0; i < values.Length; i++) values[i] = values[i].Trim('"');
                return values;
            });

            var TemplateTcpStr = TemplateTcp.ToString();
            var TemplateUdpStr = TemplateUdp.ToString();

            // Parse them into servers.
            return servers.SelectMany((server) =>
            {
                var currTemplateTcp = TemplateTcpStr.Replace(s_TemplateKeyOvpnHostname, server[3]);
                var currTemplateUdp = TemplateUdpStr.Replace(s_TemplateKeyOvpnHostname, server[3]);

                var parsed = Enumerable.Empty<IVPNServer>();
                for (int i = 0; i < 2; i++)
                {
                    string currTemplate = null;
                    string type = null;
                    if (i == 0)
                    {
                        currTemplate = currTemplateTcp;
                        type = "TCP";
                    }
                    else if (i == 1)
                    {
                        currTemplate = currTemplateUdp;
                        type = "UDP";
                    }

                    var DispName = new StringBuilder(server[1]).Append(" - ").Append(server[2]).Append(" - ").Append(type).ToString();

                    var registry = CreateExtraRegistry();
                    registry.Add(ServerRegistryKeys.DisplayName, DispName);
                    registry.Add(ServerRegistryKeys.Country, server[0]);
                    registry.Add(ServerRegistryKeys.Username, ovpnUser);
                    registry.Add(ServerRegistryKeys.Password, ovpnPass);

                    parsed = parsed.Concat(OpenVpnServer.ParseConfigFull(currTemplate, registry));
                }

                return parsed;
            });
        }
    }
}
