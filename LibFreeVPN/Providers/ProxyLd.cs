using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
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
    public class ProxyLd : VPNProviderBase
    {
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5uZXNjLmFkYmxvY2twbHVzdnBu";

        public override string SampleVersion => "3.3.3";

        public override bool RiskyRequests => true;

        private static readonly byte[] s_AesKey = "NzRsZGhmbGQwMmtkbGFuYw==".FromBase64String();
        private static readonly byte[] s_AesIv = "amRrYWxwbW5xdXp2c3Rodw==".FromBase64String();

        private static readonly string s_C2PostData = Encoding.ASCII.FromBase64String("eyJ0YWJsZSI6InNzbCJ9");
        private static readonly string s_C2Uri = Encoding.ASCII.FromBase64String("aHR0cHM6Ly90aW1lLmRhbHZpa3N5c3RlbXMuY29tL2Z1bmN0aW9ucy92MS9hbGFybS1ub3RpZmljYXRpb24=");
        private static readonly string s_C2UserAgent = Encoding.ASCII.FromBase64String("b2todHRwLzQuMTIuMA==");
        private static readonly string s_C2Header = Encoding.ASCII.FromBase64String("VGltZQ==");


        public override bool HasProtocol(ServerProtocol protocol)
            => protocol == ServerProtocol.WebProxy;

        private static IEnumerable<IVPNServer> ParseConfig(JsonElement elem, Dictionary<string, string> registry)
        {
            if (elem.ValueKind != JsonValueKind.Object) return null;
            if (!elem.TryGetPropertyString("server", out var server)) return null;
            if (!elem.TryGetProperty("port", out var port)) return null;
            if (port.ValueKind != JsonValueKind.Number) return null;
            if (!port.TryGetInt32(out var portInt)) return null;
            if (!elem.TryGetPropertyString("username", out var username)) return null;
            if (!elem.TryGetPropertyString("password", out var password)) return null;

            var ub = new UriBuilder();
            if (!server.StartsWith("https://"))
            {
                ub.Scheme = "http";
                ub.Host = server;
            } else
            {
                var uri = new Uri(server);
                ub.Scheme = uri.Scheme;
                ub.Host = uri.Host;
            }
            ub.Port = portInt;
            ub.UserName = username;
            ub.Password = password;


            registry.Add(ServerRegistryKeys.DisplayName, server.Replace("https://", ""));
            registry.Add(ServerRegistryKeys.Username, username);
            registry.Add(ServerRegistryKeys.Password, password);

            return WebProxyServer.ParseConfigFull(ub.ToString(), registry);
        }

        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            string response = null;
            using (var request = new HttpRequestMessage(HttpMethod.Post, s_C2Uri))
            {
                request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(s_C2PostData));
                request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
                request.Headers.UserAgent.Clear();
                request.Headers.UserAgent.TryParseAdd(s_C2UserAgent);
                request.Headers.Add(s_C2Header, DateTime.UtcNow.ToString("hh:mm:ss"));

                var post = await ServerUtilities.HttpClient.SendAsync(request);
                response = await post.Content.ReadAsStringAsync();
            }

            // Decrypt the response.
            using (var aes = new AesManaged())
            {
                var cipherText = Convert.FromBase64String(response);
                aes.BlockSize = 128;
                aes.KeySize = 128;
                aes.Padding = PaddingMode.PKCS7;
                using (var dec = aes.CreateDecryptor(s_AesKey, s_AesIv))
                {
                    response = Encoding.UTF8.GetString(dec.TransformFinalBlock(cipherText, 0, cipherText.Length));
                }
            }

            // Parse the response.
            var json = JsonDocument.Parse(response);
            if (json.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException();
            return json.RootElement.EnumerateArray().SelectMany((elem) =>
            {
                var ret = ParseConfig(elem, CreateExtraRegistry());
                if (ret == null) ret = Enumerable.Empty<IVPNServer>();
                return ret;
            });
        }
    }
}
