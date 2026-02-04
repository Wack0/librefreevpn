using LibFreeVPN.Memecrypto;
using LibFreeVPN.ProviderHelpers;
using LibFreeVPN.Servers;
using LibFreeVPN.Servers.V2Ray;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

// Android apps. Gives out v2ray configs. Risky requests (actual C2 domain obtained from github repo)
// The github account involved has almost 200 repos at time of implementation.
namespace LibFreeVPN.Providers.Addy
{
    public abstract class AddyParserBase<TParser> : VPNGenericMultiProviderParser<TParser>
        where TParser : AddyParserBase<TParser>, new()
    {
        // final bit of trickery:
        // v2ray ID is crypted by AES-128-CBC (ciphertext is encoded by url-safe base64)
        // and then the GUID bytes are additionally XORed by a constant pad
        // this final memecrypto is done inside the v2ray golang lib
        protected abstract byte[] IdKey { get; }
        protected abstract byte[] IdIv { get; }

        protected virtual byte[] IdXorKey => ("WBT4YEHBbMK6a5tmoVHOXA==").FromBase64String();

        private string DecryptInner(string ciphertext)
        {
            var cipherTextBytes = Convert.FromBase64String(ciphertext.Replace("-", "+").Replace("_", "/"));
            using (var aes = new AesManaged())
            {
                aes.BlockSize = 128;
                aes.KeySize = 128;
                aes.Padding = PaddingMode.PKCS7;
                using (var dec = aes.CreateDecryptor(IdKey, IdIv))
                {
                    var guid = Guid.Parse(Encoding.UTF8.GetString(dec.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length)));
                    var bytes = guid.ToByteArray();
                    var xorKey = IdXorKey;
                    if (!BitConverter.IsLittleEndian)
                        for (int i = 0; i < bytes.Length; i++) bytes[i] ^= xorKey[i];
                    else
                    {
                        for (int i = 0; i < 4; i++) bytes[i] ^= xorKey[3 - i];
                        for (int i = 4; i < 8; i++) bytes[i] ^= xorKey[i ^ 1];
                        for (int i = 8; i < bytes.Length; i++) bytes[i] ^= xorKey[i];
                    }
                    return new Guid(bytes).ToString();
                }
            }
        }

        private string DecryptAllInner(string config)
        {
            var json = JsonDocument.Parse(config);
            if (json.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            if (!json.RootElement.TryGetProperty("outbounds", out var serversElem)) throw new InvalidDataException();
            if (serversElem.ValueKind != JsonValueKind.Array) throw new InvalidDataException();

            var outbounds = serversElem.Deserialize<List<Outbounds4Ray>>();

            foreach (var outbound in outbounds)
            {
                if (outbound?.settings?.vnext == null) continue;
                foreach (var vnext in outbound.settings.vnext)
                {
                    if (vnext.users == null) continue;
                    foreach (var user in vnext.users) {
                        config = config.Replace(user.id, DecryptInner(user.id));
                    }
                }
            }

            return config;
        }

        public override IEnumerable<IVPNServer> Parse(string config, IReadOnlyDictionary<string, string> extraRegistry)
        {
            var json = JsonDocument.Parse(config);
            if (json.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException();
            return json.RootElement.EnumerateArray().SelectMany((op) =>
            {
                if (!op.TryGetProperty("countries", out var countries)) return Enumerable.Empty<JsonElement>();
                if (countries.ValueKind != JsonValueKind.Array) return Enumerable.Empty<JsonElement>();

                return countries.EnumerateArray();
            }).SelectMany((opC) =>
            {
                if (!opC.TryGetPropertyString("name", out var country)) country = string.Empty;

                if (!opC.TryGetProperty("servers", out var servers)) return Enumerable.Empty<IVPNServer>();
                if (servers.ValueKind != JsonValueKind.Array) return Enumerable.Empty<IVPNServer>();

                return servers.EnumerateArray().SelectMany((server) =>
                {
                    if (!server.TryGetPropertyString("address", out var thisConfig)) return Enumerable.Empty<IVPNServer>();
                    if (!server.TryGetPropertyString("name", out var name)) name = string.Empty;
                    var registry = new Dictionary<string, string>();
                    foreach (var kv in extraRegistry) registry.Add(kv.Key, kv.Value);
                    if (!string.IsNullOrEmpty(name)) registry.Add(ServerRegistryKeys.DisplayName, name);
                    if (!string.IsNullOrEmpty(country)) registry.Add(ServerRegistryKeys.Country, country);


                    return V2RayServer.ParseConfigFull(DecryptAllInner(thisConfig), registry);
                });
            }).ToList();
        }
    }
    public abstract class AddyBase<TParser> : VPNProviderGithubRepoFileBase
        where TParser : AddyParserBase<TParser>, new()
    {
        private static ConcurrentDictionary<string, byte> s_KnownC2s = new ConcurrentDictionary<string, byte>(); // to ensure that each known C2 is only hit once, for several clients using the same C2

        public override bool RiskyRequests => true; // github repo request is here only used to get the actual C2 server

        public override bool HasProtocol(ServerProtocol protocol)
            => protocol == ServerProtocol.V2Ray;

        protected virtual string AccountName => Encoding.ASCII.FromBase64String("YWR5bW9iMjAyNA==");
        protected abstract string C2RepoName { get; }

        private static string RepoNameGetter(AddyBase<TParser> self) => string.Format("{0}/{1}", self.AccountName, self.C2RepoName);

        protected sealed override string RepoName => this.SingleInstanceByType(RepoNameGetter);
        protected override string ConfigName => Encoding.ASCII.FromBase64String("ZG9tYWluLnR4dA==");

        protected abstract string OuterSeed { get; }
        protected virtual byte[] OuterIV => ("NTE4MzY2NmM3MmVlYzllNA==").FromBase64String();

        // cert chain that signed app, sent to C2 as part of request
        // this starts from the third match of 30 82 in BNDLTOOL.RSA
        // the following two bytes are big endian 16 bit length, take that plus the 4 byte header
        // google now signs all apps, so one should work for all. 
        protected virtual byte[] CertificateChain => (
            "MIIFiTCCA3GgAwIBAgIVAKfhhsKa2RO2DvTIP8RbTgygit6vMA0GCSqGSIb3DQEBCwUAMHQxCzAJ" +
            "BgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRQw" +
            "EgYDVQQKEwtHb29nbGUgSW5jLjEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UEAxMHQW5kcm9pZDAg" +
            "Fw0yMzA4MDUwODA5NDJaGA8yMDUzMDgwNTA4MDk0MlowdDELMAkGA1UEBhMCVVMxEzARBgNVBAgT" +
            "CkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxFDASBgNVBAoTC0dvb2dsZSBJbmMu" +
            "MRAwDgYDVQQLEwdBbmRyb2lkMRAwDgYDVQQDEwdBbmRyb2lkMIICIjANBgkqhkiG9w0BAQEFAAOC" +
            "Ag8AMIICCgKCAgEAjQ3bZOaGhWUnEyQwFibvoOQuIf9mRnKb6kz4BrWjqzXc5JZ8eg+Bpj9jP8Nt" +
            "UVUd8g7Lu8856w+//EoZR1plCk/bZ4RKbvDSmE+0OuZkAg+JFlamnFeUhO1GNpCcpnsuoMqsOQz0" +
            "KcD8VreIl19vy0x6ry9PAJZhfkb+ulkaChhUgDbO9rAnYVMbTdZq3/OQ0SwOfCXPGZoTpf1tkBeP" +
            "UeezLUSYMa0z7ey8tx48k110AZjVVsBju89a6NJFAYS4cyAgEfgAYN3CnnkzDcPmEG9lD4SDA0r1" +
            "wu+LY0vW4OStUF6X+OhVI0b3GTINvYHpJLwAIQ09IwdvcHq4NVBzLFRWgiAylGxjCDKKLvFUu4uK" +
            "Gpb4G4sTB8ws4BDMgW17WQWcT5Pj5FACMP1U67cFam6md4xMMo2oENpwdcJvoiR0jsPpHeoAWQq3" +
            "d0K8AKcQ9jeohVVVk8jo9KkTXSIzYZVgha1wsMjyEqd4sEBhGaehXUMdB3/nWvSL43Yi5hovF19c" +
            "ZHJon+qTpNEXWrynAlGlpy8QF4RRwkUN2bt3OEcqldw1tCGkguF6Vn9uuxq6zA1yWUyqnB6O1dp/" +
            "KsfAoq7qxMffqLFCjwPYHnRWlPevD6z7lMZfQOv3lrNf5UYi07kMU4R94eoI42jvJt8uuLS9eRqO" +
            "FwhQk/mZFp/2axsCAwEAAaMQMA4wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAg0cs" +
            "I/FgrzF8rPJng3U4Wi1DkytNPPA1Csee2zHbGpv8Go7xlr3SQpXY2idAx1ZpbjtybzZ6NtQDbG4V" +
            "sUHttXDDWW8Xs7QDZF4IIq6fc8Lo8xQCbzKasaRS1UZItpjoi7cokNteY5FUra1bl7v/NepwQZIU" +
            "ntLs8jjNa4TgPErj8RKtNrlWnCKSKNOADb6Kvn+vZupGjNvm6MZNZIT4PMNzgog84ciUy+KxGW+F" +
            "zUT6bfqJwpuhdb4H7dEbqG04gGJvLPYOmqjrPPxtevWQbnUz+lpUWmIwRgRI2IUvT2v9w6wTqKPx" +
            "URJVp8AGBFeBpeNBq1ux5HTn/390vbNu/ZHESIMoMS/48VM3P2bNqXvYqE2Wj9atslcX5kDGjIDt" +
            "CWjGim2Zj28NjFLlLM7E0XEs3q2fsBfqRL8Crw9cWJjYGCB88PVdM0DkjnEbHHFe2p1LWWNroC4P" +
            "uQb9da3IyCyqlpbAxvQ+zxUopre7mFdiPwt5b6xrMY3MFEx9+hoMjMC1/LhAhaYoSnaKce7Cl0Nn" +
            "GrGzKebAKGFySDp+7Shy2HqPWOwZmfOMLHT/Boz+lPnkECEm0/CDYoq+F23/t4VjU0S9NzZdy4i2" +
            "uN4NDCJrJctHkaWDfW3AJ135xw48e7kB9YVlIYiziGTgXzCJnHGY6pSwiWOMlaqEYrTItKs=").FromBase64String();

        protected virtual string C2Authorisation => Encoding.ASCII.FromBase64String("QXBpS2V5IDY1YTU4NzI4LXJ0NDUtMjVoYS1iMnJlLTQzNTY3NDUyODkwYQ==");
        protected abstract string C2ApiKey { get; }

        private static readonly byte[] s_C2KeyFirst = Convert.FromBase64String("i3pp+O21/3M=");
        private static readonly byte[] s_C2IV = Convert.FromBase64String("d6f2t979uMNp9ctvCQjslQ==");

        private static readonly string s_ApiKeyHeader = Encoding.ASCII.GetString(Convert.FromBase64String("YXBwQXBpS2V5"));
        private static readonly string s_RandomDataHeader = Encoding.ASCII.GetString(Convert.FromBase64String("dW5pcXVlRGV2aWNlSUQ="));
        private static readonly string s_SampleVersionHeader = Encoding.ASCII.GetString(Convert.FromBase64String("YXBwVmVyc2lvbk5hbWU="));
        private static readonly string s_EncipheredHeader = Encoding.ASCII.GetString(Convert.FromBase64String("cXdlcg=="));

        private static readonly string s_RandomDataPostQuery = Encoding.ASCII.GetString(Convert.FromBase64String("dW5pcXVlRGV2aWNlSWQ9"));

        private static readonly string s_RandomDataInsertPath = Encoding.ASCII.GetString(Convert.FromBase64String("L2FwaS92MS91c2Vycy9hZHZlcnRpc2U="));
        private static readonly string s_GetServersPath = Encoding.ASCII.GetString(Convert.FromBase64String("L2FwaS92Ni9wcm9maWxlcw=="));


        private static readonly RNGCryptoServiceProvider s_Csprng = new RNGCryptoServiceProvider();


        private string DecryptFromServer(string ciphertext, string saltPrefix)
        {
            // Calculate the key:
            byte[] key = null;
            using (var hash = MD5.Create())
            {
                var h = hash.ComputeHash(Encoding.UTF8.GetBytes(saltPrefix + OuterSeed));
                key = Encoding.ASCII.GetBytes(BitConverter.ToString(h).ToLower().Replace("-", ""));
            }

            return Encoding.UTF8.GetString(AesCtr.Transform(key, OuterIV, Convert.FromBase64String(ciphertext)));
        }

        private string DecryptFromServer(string ciphertext) => DecryptFromServer(ciphertext, string.Empty);

        private string CreateEncipheredHeader()
        {
            var rng = new byte[4];
            s_Csprng.GetBytes(rng);
            var plaintext = Encoding.UTF8.GetBytes(string.Format("{0}|{1}|{2}{3:d4}",
                Guid.NewGuid(),
                BitConverter.ToString(CertificateChain).ToLower().Replace("-", ""),
                DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                new Random(BitConverter.ToInt32(rng, 0)).Next(10000)
            ));
            var key = new byte[0x10];
            Buffer.BlockCopy(s_C2KeyFirst, 0, key, 0, 8);
            s_Csprng.GetBytes(key, 8, 8);
            using (var aes = new AesManaged())
            {
                aes.BlockSize = 128;
                aes.KeySize = 128;
                aes.Padding = PaddingMode.PKCS7;
                using (var dec = aes.CreateEncryptor(key, s_C2IV))
                {
                    return Convert.ToBase64String(dec.TransformFinalBlock(plaintext, 0, plaintext.Length));
                }
            }
        }

        private void InitHeaders(HttpRequestHeaders headers, string randomData)
        {
            headers.Authorization = AuthenticationHeaderValue.Parse(C2Authorisation);
            headers.Add(s_ApiKeyHeader, C2ApiKey);
            headers.Add(s_RandomDataHeader, randomData);
            headers.Add(s_SampleVersionHeader, SampleVersion);
            headers.Add(s_EncipheredHeader, CreateEncipheredHeader());
        }

        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl(string c2)
        {
            // Decrypt the C2 server.
            c2 = DecryptFromServer(c2);

            // Ensure it looks correct.
            if (!c2.StartsWith("http")) throw new InvalidDataException();

            if (c2.EndsWith("/")) c2 = c2.Substring(0, c2.Length - 1);

            // Make sure this C2 server hasn't been contacted this session.
            if (!s_KnownC2s.TryAdd(c2, 1)) return Enumerable.Empty<IVPNServer>();

            // Generate some random data.
            string randomData;
            {
                var randomBytes = new byte[8];
                s_Csprng.GetBytes(randomBytes);
                randomData = BitConverter.ToUInt64(randomBytes, 0).ToString("x16");
            }

            // TRADE OFFER:
            // i receive: vpn servers
            // you receive: lots of junk in your database of "unique device IDs for tracking"

            using (var request = new HttpRequestMessage(HttpMethod.Post, c2 + s_RandomDataInsertPath))
            {
                request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(s_RandomDataPostQuery + randomData));
                request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded");
                InitHeaders(request.Headers, randomData);
                var post = await ServerUtilities.HttpClient.SendAsync(request);
                await post.Content.ReadAsStringAsync();

                // don't even bother looking at what was returned, the only thing that mattered was the prerequisite db insert to make the following request.
            }

            // now make the actual request to get the servers:
            HttpResponseMessage response = null;
            using (var request = new HttpRequestMessage(HttpMethod.Get, c2 + s_GetServersPath))
            {
                InitHeaders(request.Headers, randomData);
                response = await ServerUtilities.HttpClient.SendAsync(request);
            }

            var serversText = await response.Content.ReadAsStringAsync();

            // Pull the ciphertext out of the json object.
            var serversResponseJson = JsonDocument.Parse(serversText);
            if (serversResponseJson.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            if (!serversResponseJson.RootElement.TryGetPropertyString("data", out var servers)) throw new InvalidDataException();

            // And decrypt it.
            servers = DecryptFromServer(servers, randomData);

            // And parse what was obtained.
            return await GetServersAsyncImpl<TParser>(servers);
        }
    }

    public sealed class AddyPro : AddyBase<AddyPro.Parser>
    {
        public sealed class Parser : AddyParserBase<Parser>
        {
            protected override byte[] IdKey => ("TXFwV3o5Sk5mS3NHeFVkNg==").FromBase64String();
            protected override byte[] IdIv => ("a05nRDRMeDlSVm1qdXRFaw==").FromBase64String();
        }
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS52cG4udjJwcm8=";

        public override string SampleVersion => "90.0";

        protected override string C2RepoName => Encoding.ASCII.FromBase64String("djJwcm92cG4=");

        protected override string OuterSeed => Encoding.ASCII.FromBase64String(
            "MzA4MjA1ODkzMDgyMDM3MWEwMDMwMjAxMDIwMjE1MDBhN2UxODZjMjlhZDkxM2I2MGVmNGM4M2Zj" +
            "NDViNGUwY2EwOGFkZWFmMzAwZDA2MDkyYTg2NDg4NmY3MGQwMTAxMGIwNTAwMzA3NDMxMGIzMDA5" +
            "MDYwMzU1MDQwNjEzMDI1NTUzMzExMzMwMTEwNjAzNTUwNDA4MTMwYTQzNjE2YzY5NjY2ZjcyNmU2" +
            "OTYxMzExNjMwMTQwNjAzNTUwNDA3MTMwZDRkNmY3NTZlNzQ2MTY5NmUyMDU2Njk2NTc3MzExNDMw" +
            "MTIwNjAzNTUwNDBhMTMwYjQ3NmY2ZjY3NmM2NTIwNDk2ZTYzMmUzMTEwMzAwZTA2MDM1NTA0MGIx" +
            "MzA3NDE2ZTY0NzI2ZjY5NjQzMTEwMzAwZTA2MDM1NTA0MDMxMzA3NDE2ZTY0NzI2ZjY5NjQzMDIw" +
            "MTcwZDMyMzMzMDM4MzAzNTMwMzgzMDM5MzQzMjVhMTgwZjMyMzAzNTMzMzAzODMwMzUzMDM4MzAz" +
            "OTM0MzI1YTMwNzQzMTBiMzAwOTA2MDM1NTA0MDYxMzAyNTU1MzMxMTMzMDExMDYwMzU1MDQwODEz" +
            "MGE0MzYxNmM2OTY2NmY3MjZlNjk2MTMxMTYzMDE0MDYwMzU1MDQwNzEzMGQ0ZDZmNzU2ZTc0NjE2" +
            "OTZlMjA1NjY5NjU3NzMxMTQzMDEyMDYwMzU1MDQwYTEzMGI0NzZmNmY2NzZjNjUyMDQ5NmU2MzJl" +
            "MzExMDMwMGUwNjAzNTUwNDBiMTMwNzQxNmU2NDcyNmY2OTY0MzExMDMwMGUwNjAzNTUwNDAzMTMw" +
            "NzQxNmU2NDcyNmY2OTY0MzA4MjAyMjIzMDBkMDYwOTJhODY0ODg2ZjcwZDAxMDEwMTA1MDAwMzgy" +
            "MDIwZjAwMzA4MjAyMGEwMjgyMDIwMTAwOGQwZGRiNjRlNjg2ODU2NTI3MTMyNDMwMTYyNmVmYTBl" +
            "NDJlMjFmZjY2NDY3MjliZWE0Y2Y4MDZiNWEzYWIzNWRjZTQ5NjdjN2EwZjgxYTYzZjYzM2ZjMzZk" +
            "NTE1NTFkZjIwZWNiYmJjZjM5ZWIwZmJmZmM0YTE5NDc1YTY1MGE0ZmRiNjc4NDRhNmVmMGQyOTg0" +
            "ZmI0M2FlNjY0MDIwZjg5MTY1NmE2OWM1Nzk0ODRlZDQ2MzY5MDljYTY3YjJlYTBjYWFjMzkwY2Y0" +
            "MjljMGZjNTZiNzg4OTc1ZjZmY2I0YzdhYWYyZjRmMDA5NjYxN2U0NmZlYmE1OTFhMGExODU0ODAz" +
            "NmNlZjZiMDI3NjE1MzFiNGRkNjZhZGZmMzkwZDEyYzBlN2MyNWNmMTk5YTEzYTVmZDZkOTAxNzhm" +
            "NTFlN2IzMmQ0NDk4MzFhZDMzZWRlY2JjYjcxZTNjOTM1ZDc0MDE5OGQ1NTZjMDYzYmJjZjVhZThk" +
            "MjQ1MDE4NGI4NzMyMDIwMTFmODAwNjBkZGMyOWU3OTMzMGRjM2U2MTA2ZjY1MGY4NDgzMDM0YWY1" +
            "YzJlZjhiNjM0YmQ2ZTBlNGFkNTA1ZTk3ZjhlODU1MjM0NmY3MTkzMjBkYmQ4MWU5MjRiYzAwMjEw" +
            "ZDNkMjMwNzZmNzA3YWI4MzU1MDczMmM1NDU2ODIyMDMyOTQ2YzYzMDgzMjhhMmVmMTU0YmI4Yjhh" +
            "MWE5NmY4MWI4YjEzMDdjYzJjZTAxMGNjODE2ZDdiNTkwNTljNGY5M2UzZTQ1MDAyMzBmZDU0ZWJi" +
            "NzA1NmE2ZWE2Nzc4YzRjMzI4ZGE4MTBkYTcwNzVjMjZmYTIyNDc0OGVjM2U5MWRlYTAwNTkwYWI3" +
            "Nzc0MmJjMDBhNzEwZjYzN2E4ODU1NTU1OTNjOGU4ZjRhOTEzNWQyMjMzNjE5NTYwODVhZDcwYjBj" +
            "OGYyMTJhNzc4YjA0MDYxMTlhN2ExNWQ0MzFkMDc3ZmU3NWFmNDhiZTM3NjIyZTYxYTJmMTc1ZjVj" +
            "NjQ3MjY4OWZlYTkzYTRkMTE3NWFiY2E3MDI1MWE1YTcyZjEwMTc4NDUxYzI0NTBkZDliYjc3Mzg0" +
            "NzJhOTVkYzM1YjQyMWE0ODJlMTdhNTY3ZjZlYmIxYWJhY2MwZDcyNTk0Y2FhOWMxZThlZDVkYTdm" +
            "MmFjN2MwYTJhZWVhYzRjN2RmYThiMTQyOGYwM2Q4MWU3NDU2OTRmN2FmMGZhY2ZiOTRjNjVmNDBl" +
            "YmY3OTZiMzVmZTU0NjIyZDNiOTBjNTM4NDdkZTFlYTA4ZTM2OGVmMjZkZjJlYjhiNGJkNzkxYThl" +
            "MTcwODUwOTNmOTk5MTY5ZmY2NmIxYjAyMDMwMTAwMDFhMzEwMzAwZTMwMGMwNjAzNTUxZDEzMDQw" +
            "NTMwMDMwMTAxZmYzMDBkMDYwOTJhODY0ODg2ZjcwZDAxMDEwYjA1MDAwMzgyMDIwMTAwODM0NzJj" +
            "MjNmMTYwYWYzMTdjYWNmMjY3ODM3NTM4NWEyZDQzOTMyYjRkM2NmMDM1MGFjNzllZGIzMWRiMWE5" +
            "YmZjMWE4ZWYxOTZiZGQyNDI5NWQ4ZGEyNzQwYzc1NjY5NmUzYjcyNmYzNjdhMzZkNDAzNmM2ZTE1" +
            "YjE0MWVkYjU3MGMzNTk2ZjE3YjNiNDAzNjQ1ZTA4MjJhZTlmNzNjMmU4ZjMxNDAyNmYzMjlhYjFh" +
            "NDUyZDU0NjQ4YjY5OGU4OGJiNzI4OTBkYjVlNjM5MTU0YWRhZDViOTdiYmZmMzVlYTcwNDE5MjE0" +
            "OWVkMmVjZjIzOGNkNmI4NGUwM2M0YWUzZjExMmFkMzZiOTU2OWMyMjkyMjhkMzgwMGRiZThhYmU3" +
            "ZmFmNjZlYTQ2OGNkYmU2ZThjNjRkNjQ4NGY4M2NjMzczODI4ODNjZTFjODk0Y2JlMmIxMTk2Zjg1" +
            "Y2Q0NGZhNmRmYTg5YzI5YmExNzViZTA3ZWRkMTFiYTg2ZDM4ODA2MjZmMmNmNjBlOWFhOGViM2Nm" +
            "YzZkN2FmNTkwNmU3NTMzZmE1YTU0NWE2MjMwNDYwNDQ4ZDg4NTJmNGY2YmZkYzNhYzEzYThhM2Yx" +
            "NTExMjU1YTdjMDA2MDQ1NzgxYTVlMzQxYWI1YmIxZTQ3NGU3ZmY3Zjc0YmRiMzZlZmQ5MWM0NDg4" +
            "MzI4MzEyZmY4ZjE1MzM3M2Y2NmNkYTk3YmQ4YTg0ZDk2OGZkNmFkYjI1NzE3ZTY0MGM2OGM4MGVk" +
            "MDk2OGM2OGE2ZDk5OGY2ZjBkOGM1MmU1MmNjZWM0ZDE3MTJjZGVhZDlmYjAxN2VhNDRiZjAyYWYw" +
            "ZjVjNTg5OGQ4MTgyMDdjZjBmNTVkMzM0MGU0OGU3MTFiMWM3MTVlZGE5ZDRiNTk2MzZiYTAyZTBm" +
            "YjkwNmZkNzVhZGM4YzgyY2FhOTY5NmMwYzZmNDNlY2YxNTI4YTZiN2JiOTg1NzYyM2YwYjc5NmZh" +
            "YzZiMzE4ZGNjMTQ0YzdkZmExYTBjOGNjMGI1ZmNiODQwODVhNjI4NGE3NjhhNzFlZWMyOTc0MzY3" +
            "MWFiMWIzMjllNmMwMjg2MTcyNDgzYTdlZWQyODcyZDg3YThmNThlYzE5OTlmMzhjMmM3NGZmMDY4" +
            "Y2ZlOTRmOWU0MTAyMTI2ZDNmMDgzNjI4YWJlMTc2ZGZmYjc4NTYzNTM0NGJkMzczNjVkY2I4OGI2" +
            "YjhkZTBkMGMyMjZiMjVjYjQ3OTFhNTgzN2Q2ZGMwMjc1ZGY5YzcwZTNjN2JiOTAxZjU4NTY1MjE4" +
            "OGIzODg2NGUwNWYzMDg5OWM3MTk4ZWE5NGIwODk2MzhjOTVhYTg0NjJiNGM4YjRhYmNvbS52cG4u" +
            "djJwcm8=");

        protected override string C2ApiKey => Encoding.ASCII.FromBase64String("NGQwN2E1MDEtODBhNi00MzI2LWE4YWItZDYzMDUyMGY0N2Vi");
    }

    public sealed class AddyV2V : AddyBase<AddyV2V.Parser>
    {
        public sealed class Parser : AddyParserBase<Parser>
        {
            protected override byte[] IdKey => ("WWhOY1F3eDJrc01WbkpqdA==").FromBase64String();
            protected override byte[] IdIv => ("dFp3bjNwTGpLZm1SUWpoNg==").FromBase64String();
        }


        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS52MnJheS52MnZwbg==";

        public override string SampleVersion => "90.0";

        protected override string C2RepoName => Encoding.ASCII.FromBase64String("djJ2cG4=");

        protected override string OuterSeed => Encoding.ASCII.FromBase64String(
            "MzA4MjA1ODgzMDgyMDM3MGEwMDMwMjAxMDIwMjE0Njc1OGE3MGJiMzZkZTg5MDA2OGM0NGFkN2Fh" +
            "Y2MzOTE2Mjk1ZDEwOTMwMGQwNjA5MmE4NjQ4ODZmNzBkMDEwMTBiMDUwMDMwNzQzMTBiMzAwOTA2" +
            "MDM1NTA0MDYxMzAyNTU1MzMxMTMzMDExMDYwMzU1MDQwODEzMGE0MzYxNmM2OTY2NmY3MjZlNjk2" +
            "MTMxMTYzMDE0MDYwMzU1MDQwNzEzMGQ0ZDZmNzU2ZTc0NjE2OTZlMjA1NjY5NjU3NzMxMTQzMDEy" +
            "MDYwMzU1MDQwYTEzMGI0NzZmNmY2NzZjNjUyMDQ5NmU2MzJlMzExMDMwMGUwNjAzNTUwNDBiMTMw" +
            "NzQxNmU2NDcyNmY2OTY0MzExMDMwMGUwNjAzNTUwNDAzMTMwNzQxNmU2NDcyNmY2OTY0MzAyMDE3" +
            "MGQzMjMzMzAzNzMyMzUzMDM4MzMzNDMxMzI1YTE4MGYzMjMwMzUzMzMwMzczMjM1MzAzODMzMzQz" +
            "MTMyNWEzMDc0MzEwYjMwMDkwNjAzNTUwNDA2MTMwMjU1NTMzMTEzMzAxMTA2MDM1NTA0MDgxMzBh" +
            "NDM2MTZjNjk2NjZmNzI2ZTY5NjEzMTE2MzAxNDA2MDM1NTA0MDcxMzBkNGQ2Zjc1NmU3NDYxNjk2" +
            "ZTIwNTY2OTY1NzczMTE0MzAxMjA2MDM1NTA0MGExMzBiNDc2ZjZmNjc2YzY1MjA0OTZlNjMyZTMx" +
            "MTAzMDBlMDYwMzU1MDQwYjEzMDc0MTZlNjQ3MjZmNjk2NDMxMTAzMDBlMDYwMzU1MDQwMzEzMDc0" +
            "MTZlNjQ3MjZmNjk2NDMwODIwMjIyMzAwZDA2MDkyYTg2NDg4NmY3MGQwMTAxMDEwNTAwMDM4MjAy" +
            "MGYwMDMwODIwMjBhMDI4MjAyMDEwMDhjNDlkMGYwZmM0MDIxYTkzMzE0ODg4ZjliMzllOTQ5MWMz" +
            "MjgzZWIxZjkzNTQ5OWMxNmJhMzQ1ODA2NTMyZWUyOGFhNGQ2Mzc5ODg2ZDg5NmEyNDAzNWViYjYx" +
            "MDk2ZTc4MDhhYTUwMGJmNzU4MWMyZTgxYjc1MTYyZDEyOTM1OWNiMjIyNjM1ZWI0YzAyZDhmNjg0" +
            "ZjFkYTdkMzk4YWEyOTkxMzVhN2QxMTk2NmRkNmE4MWNhNGExNzBjNDY2NjYyNzI1NmUzNjVhZmNl" +
            "YjUxOWRlZDJiYjhmMTc4MzI5YTU0YjQ4ZGYxNTE1M2UwOTgzMzUyNjI5YmYxMGEyYTg0OTBhMTk1" +
            "MmFjMjcxZjgwZmM3MzllNjI3NWRmMjM4N2M5OWQwNzViMGIxMWUwN2JhNzVjYTlkNjZkZmMyNGE4" +
            "NGI2ZmU3MjhhNDJjMTRkY2JmNThmMGI3YTdhZmU1OWYzMGU2NTA4ZDEzYzYyOTcyYTFiYjQxYjg4" +
            "ZDVhYjYwNzBlZjAwM2UzOWNjNTI0MTk0MzNjYzQ4MTc5Mjc3ODk3NjJkMzEwNjU4M2ZhM2EyZjNj" +
            "YmI3YzFlZjYzZWVhYmQ0NTllY2E0YzQwZjY2MGVlYjVhMDY1YzQ0ZTU5OTIyMGFlY2RhMzA3Yjgw" +
            "MDE4OGJhZmM4NTk0MmVmNjczNTY5MDcxNTQyZDVlZjI1MDQyODU3MzI2ZWI2YjliYzQ3NDIyNzJm" +
            "MTM1NDExYWIwODdlMTgwY2U5OGU3MDQzNjY5OGEwODAyNTgyN2FiOWFlMTM3OGExNWMxZGRmYzE4" +
            "NzVkNTVmNzdlNTlmOTI1NDlkOGZhZDFkZjAyMjFhOTYwNGU4YmEwMzdmN2E5ZTUxNThhMTMyM2Q1" +
            "YWRlYzEyZWRlM2QxMmUwNTQxNWE3MjlkYjNmNTZmNjgyZTgyZTZmODhmYjUyMTI1YWI1YzQwNWY1" +
            "YTY1MTBjZGEzMjRhM2ZmMzBhOGU0MTY3YTk4ZTQ0ZmJiMjZiZDMyOTZkNDliMmU4NGY5NWRlNDJh" +
            "MDIwYTc5MDM0ZGQzNTBkM2Q3YTZlZjJjNTBjMTY3ZmE3N2UzMjc3MWI5ZDgzY2Q4ZWYyMWZjMWM5" +
            "OTFiOWQ5NmE0ZWY0M2U4YmYxN2VkM2UwMmViMjUxZDczMWUzNmZmYzQ5MTdhNTQ1MjY3YWJkYTg4" +
            "ZmZlNjc2MGU5ZDEzZDE4ODM0NWE0ODAxODA2NmIxNGZhNDRiNWYzNWQxODMzZWVmYzA3MGM4Mzlj" +
            "YTk2YTkyYWIxNzgwYjJkMjIwYzQ3NzU2YWU3Nzg2NWJlNGE0OTFhMmY5MDY1MGNkNDViYTJmZGYw" +
            "MDAwNGE4NTEyMmY1MTgwNTFhMjMwMjAzMDEwMDAxYTMxMDMwMGUzMDBjMDYwMzU1MWQxMzA0MDUz" +
            "MDAzMDEwMWZmMzAwZDA2MDkyYTg2NDg4NmY3MGQwMTAxMGIwNTAwMDM4MjAyMDEwMDE4N2M1MzRk" +
            "Zjk3NjhlNGRmNzBlZjdhMGYyOTQ5ZTUyY2I2MGI3YmM4MjVmOGQyYjgwOTMwNGM5MDgzM2ZjZjc0" +
            "N2U1NzhiMjEyNTQ0OTlhY2I1ZWM5ZWU3MjNlMDU5YmRlZDk1ZjRjNDJhYTQxYTg4OGNmMjQxM2Ni" +
            "ZWM1ODc1MDk2MDA5MTQ2YjM3NGNlODQxZjdiOTAzNjI1MjA0YzNjMGIzOTEyMDhiMmU0YzM3YmVl" +
            "NTNhYTljMTg5N2YzZTA5YmU2OTM0MTg1YWZjYWQ1ZDczNDgyOGUxMjYzYTA2YWE3ODEwMTZiMjE4" +
            "MDNjZDdhYWYwMDk1MGNhODE3MGMzZDQyNmIxMGRmOTBmZmUxZTFiMzdhYjdkZGUzY2IyMzY0ZGE5" +
            "NmQ2MTYyNjhhZjk5YzVjY2RmNWEyZGFlYTcxMGNlNTA0NDg0YmI3ZDJmNDNlNDRlOTFmNzgxZTI0" +
            "ZGUyZjc1YWUxM2EyYjVmMThmNGIwOGI5YzI0NDc0YWZjNDdiOTg5ODA5NDE5ZGZiN2FmNTdhZjcy" +
            "N2Y5ZjFjNTQyYzIwMjYyNmEyZGM0M2E0ZWQzOTM5MTM0NmE3Yzk0YzA3YzZhZDRmOGQ4OTU1MzMy" +
            "ODgzNDcxYWUzMDlkNjY2N2VlZTZhNTg3YzgxMTE3Yzg1N2M3MGNmNDU5NWE0NTA4NWZjMjA2OTJk" +
            "YmZhYmI5OGZhOThjNzYxMzI0N2E4YzI4ZmM4OWVlZGQxZDMzMWY1Yjk2M2RiOTE4OTg0ODMwOTdj" +
            "YTIwMjkwZmRkZjQwMmFjNDdjNWM2YjFjZTkyYzNiMWEyNzIyODJlMzA2ZGMwMDU3MzUzYTdlMDkz" +
            "MWZmNjc2NDA3Y2YwYzc1N2Y4MTExZDUwYzMyOTNkNmE2Mzk4ODBlZmE3OWJhNTMyZDk5Y2RiNTdh" +
            "NWQ0MDc2OThlZjY1OThiNmQzNjgzMTFhYzdjODk5NWJmZGRjOTQxZjRhNTg2M2M0MzQ1MmM0NzQz" +
            "NDhhZDdjNWEwZmNjMDg0YmU0OWZhOGQ4ZTcyMGU4NTllMGI2NzM1MTAxNmRmNjlhYzY0ZTBiZTU0" +
            "ZGM0ZGMxZjc5YjFkMGE5NzA0NTk4YjhhMTg0NTVkNjAwMjY4ZWIwNDEyOTdhZThjZTZhZDdiYTM0" +
            "ZWQ4MThhNzhkZmJhZmRhZWM4MmYyMGQzOWM4MzMyOTEwOWM2NjJiMDA1YjI1YTZkZTU2YmZmMWQy" +
            "NTQ0NjBlNGNjMTM3Y2E5ZGI1MjYzNTJiMTI5MDcxNGE3OGE4ZmE5YjcxMDkyOTgzNjFkZDI1Zjhh" +
            "NjliMThlMjgyOTI2YmZmNWU1ZDA2ZjBjM2I0YTg3MWVhOWQwMTk2N2ZhNzA2MWNjb20udjJyYXku" +
            "djJ2cG4=");

        protected override string C2ApiKey => Encoding.ASCII.FromBase64String("YWY5NDlhMDMtOWFiYy00MmFhLWE4OGEtMTM1ZWI4NGYwODA4");
    }

    public sealed class AddyBox : AddyBase<AddyBox.Parser>
    {
        public sealed class Parser : AddyParserBase<Parser>
        {
            protected override byte[] IdKey => ("Z1pWTjltcDVMbnhKUXJzdA==").FromBase64String();
            protected override byte[] IdIv => ("alRzM1JwaE12eGZMb25nWQ==").FromBase64String();
        }


        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS52cG4udjJib3g=";

        public override string SampleVersion => "90.0";

        protected override string C2RepoName => Encoding.ASCII.FromBase64String("djJib3h2cG4=");

        protected override string OuterSeed => Encoding.ASCII.FromBase64String(
            "MzA4MjA1ODkzMDgyMDM3MWEwMDMwMjAxMDIwMjE1MDBmZmQ3ZDExNTZlMzY5MDdiYzI3NWM4NDIz" +
            "NDY0MTc5MmRkNmZmODNmMzAwZDA2MDkyYTg2NDg4NmY3MGQwMTAxMGIwNTAwMzA3NDMxMGIzMDA5" +
            "MDYwMzU1MDQwNjEzMDI1NTUzMzExMzMwMTEwNjAzNTUwNDA4MTMwYTQzNjE2YzY5NjY2ZjcyNmU2" +
            "OTYxMzExNjMwMTQwNjAzNTUwNDA3MTMwZDRkNmY3NTZlNzQ2MTY5NmUyMDU2Njk2NTc3MzExNDMw" +
            "MTIwNjAzNTUwNDBhMTMwYjQ3NmY2ZjY3NmM2NTIwNDk2ZTYzMmUzMTEwMzAwZTA2MDM1NTA0MGIx" +
            "MzA3NDE2ZTY0NzI2ZjY5NjQzMTEwMzAwZTA2MDM1NTA0MDMxMzA3NDE2ZTY0NzI2ZjY5NjQzMDIw" +
            "MTcwZDMyMzMzMDM4MzAzNTMwMzczMzMyMzQzOTVhMTgwZjMyMzAzNTMzMzAzODMwMzUzMDM3MzMz" +
            "MjM0Mzk1YTMwNzQzMTBiMzAwOTA2MDM1NTA0MDYxMzAyNTU1MzMxMTMzMDExMDYwMzU1MDQwODEz" +
            "MGE0MzYxNmM2OTY2NmY3MjZlNjk2MTMxMTYzMDE0MDYwMzU1MDQwNzEzMGQ0ZDZmNzU2ZTc0NjE2" +
            "OTZlMjA1NjY5NjU3NzMxMTQzMDEyMDYwMzU1MDQwYTEzMGI0NzZmNmY2NzZjNjUyMDQ5NmU2MzJl" +
            "MzExMDMwMGUwNjAzNTUwNDBiMTMwNzQxNmU2NDcyNmY2OTY0MzExMDMwMGUwNjAzNTUwNDAzMTMw" +
            "NzQxNmU2NDcyNmY2OTY0MzA4MjAyMjIzMDBkMDYwOTJhODY0ODg2ZjcwZDAxMDEwMTA1MDAwMzgy" +
            "MDIwZjAwMzA4MjAyMGEwMjgyMDIwMTAwODhiNTA3NzlkNTkzN2FjN2E3MWQyYjFmNDI0YjVmZjNj" +
            "NWVmOWM5YjMxNGNjM2Q4MDBkODZjMGQ4NDZhOTViZmM5NzAxNDJiYTFiYmVlZWQzYjg0NjRiZDBk" +
            "ZDFlNzhiZTNjMjZlNjZmZDBmZTA0ZTI3YjZlY2QyYTk1NWEyZjJiNjczMDgwMWMxODYxMzUwYjQ3" +
            "ODFjYzAwNTBhOTE3NzNmODM0MjJjY2YwNmQ0M2MyMDJmZGFiYWU0YjgzOTIzYzhiYzAxMmJlNDJm" +
            "NzM1NTQ2ZTc0YTExYjM0Mzc2YTZmZGE2Y2E5NDFmZDY3M2IxYWIxZWFmMTIyYWQ2M2YwNmY3MjIw" +
            "ZjVlMTczNzM2ZmZkODgxOGNiOGQzOGFiNzlmOWY1MmJjNjFjZTY2ODU2M2NiNGZhZGE0MTUwYjNm" +
            "YzdmN2I5NmNkYWE0MzBkY2U5MGNmMjQ4ZGYwYTk4YjY3NTQ5MmU4ZjBiODIyMTM5ODFmYjQ3ZmU4" +
            "ZDQ4ODBkNTQ2MmFhM2Y3MDEzMjkwZWE4OTNkNzY3ODdhMGQwZjk1MzlmOTYxNWI3NGY4NDlmNDNl" +
            "MGU3YTI1N2I0OTAxMTJlYzY1YjE0YzQ4NjkzYzhmYmY5YTE1NTY1MzhkNjZiMjQ2ZTBlMDFkOTVi" +
            "ZTk1ZDAzNjNjNWYzYTQxNzdmMzQ5OTE3NGYxMzQ3MTc5NjQwYmE4Y2I1ZDU2OWQ5NjhmZjJmNDE0" +
            "MWNkZjM3MmZiN2QxNjAyNThmNWQ5YWE1ZTBjOTMyMzQwZmRhNDQ5YmRlMmQ5ZjI5YThiOWM5ZjBl" +
            "NWNhOWQ4N2MwYzBiNTYwNzI5YWYxY2ZkMTVlODMxN2I0Mzc4ZGE0NGI2YjUwNGE3YjcyOWE0MTU5" +
            "ZDVmMGM2Zjg1NDViOGM3OWVlYjU5ZmQ2NTcwZjEyOWMxZDgxYWIwYTljODIzZmY5MmYwYzI3MTll" +
            "MWMyYjAzNjcxOWZmMTU1N2YwZGIwNWE4ZGMzYTRiMWNiNDBiNDQ4ZDBiYjQ5MWExNTExZTNhMTNm" +
            "OGRhNTM1ZDMwMmRjY2ExYmNkNmJiNDBmNmYyMTAxMDg0YjAzMjcxNDYwYmRjMWI2YTNiOGZmZGQy" +
            "ODQ2MDQxYzkyMDY3ZGY2N2JkZTU3ZTZjMjhhN2I0MGI2ZDEyZGQxZjgyMjgwNmM1ZTUwMzBjYzU4" +
            "MzI2NzRhNTk1MDNhZDRkYzk5NGQyYWRkODVkNjJlMjliNGU5ZGY0M2RjNjhjYTViZTY3OGIyNWMw" +
            "ZDdkMTlmMDY5NzRmMTBhYmJlNGIyYWY0NzAwMjhjOWUxYzQ2OGM5ODRlMjVmN2Y5ZTIyN2YzMDFm" +
            "Zjg3N2I0ZmMyYTQ4OGZhYzczMjcwNTAyMDMwMTAwMDFhMzEwMzAwZTMwMGMwNjAzNTUxZDEzMDQw" +
            "NTMwMDMwMTAxZmYzMDBkMDYwOTJhODY0ODg2ZjcwZDAxMDEwYjA1MDAwMzgyMDIwMTAwMmJlYjRl" +
            "ZGQ0NmQyM2YzZmQzNDY3NjNlMzM1ZjQxMjJjYTljMmMwYmM0N2M2MWJjMzdjMjAxYzMwYTVhYTQy" +
            "YmRjZjhhNjM4NDFkMGYxNDYwNWIwMDA3MjJiNzY1NzlkOTliZTYxMzAyNGMyY2MzYjBjZmE2YjZl" +
            "ZTVlMmM2NjFjMGZkMjE1NGI3YzgyZjliZDYxN2E2M2JmYWQ5YWU2NTc3MzA2NjgxNjg0MTQyMzFl" +
            "ODc3MDBjZWRmNTVmYzIwOTQxM2FlYmU1NWFiMDQ1ZTI4M2IyZmIzZmU1OGFhNzA4N2I4MmY2ODI3" +
            "YzE4ODA4MzE1OTI3MjFjYTE3YmVhNTAxYTRiY2Y1ZmJmYzAyNTgxNTRjZTRmYjk3NWMwODUzYjcx" +
            "OTkwN2VhZTgyNTc2ZmZmZGIxZWVmOGEyNWY5ODZkOTg5NzdjNDljZjZmYjgzZjFhMGIzZDIzMDc2" +
            "YzEwMDliZGI3OGNkM2U3ZDRlYTcwYmJiMjU5ZDdjZTYzOWRkMTFmM2MyNDNkNGMzODYwNjU5YTg1" +
            "NzJiMDNiMDFhNjE1OThmMDI0YzQ3ZDdkMmU5YTIwOTQwZWE0NjM3MjhlZjAyZmRiZjBmZWRmNTcy" +
            "ZDAxZDQ0YzZlMzMwNzg0YTYzZjY1YWNiZjIwNWFhNDg4ZGZkNTVhOTc1ZmMxMzNmNGZiMjFjZjJi" +
            "ZThmNTExNmIyNzI1MjFkOWFiNTA4ZmU3NmRhYTZiMDBhOGU1Nzk4OGRkOGUwNjIwOWJmMDRhMzZm" +
            "MDM3NzQ4Mzg4MzQ0Mzg1MWY4NTNiMTMyZGYzYTFjYmM1YTI3NmFiMTU0MTEyMTE2YzEwODlhNTkw" +
            "YTQ0NDRhODliMzhiMTBjYWRlZGY5ZWVlMjBiNmE0MzEwN2FmNmVhODgyMzliY2IzNzIyM2Q4YzZk" +
            "YTE2MDE2ZWU0MDYxNmY5NTg0MGIxOTljMWI0ODg0ZTgyODJiYzFjMzM3MjU5MDJmMTcyYTNkZGY0" +
            "Njc0OGYyOGFmNDYzNmRkMDg0OTRlMWI0NGJkOGZmZTk0NDczZTUyN2Q1OTc1YTYzZmNiM2IzNzBl" +
            "MTgzYTVhMDZlYjczMzczZWRkY2FhNzdlYWU2NzQyYzk1OGFiNTY0NTkwZWU1NTk0MTgwNTNhNmNl" +
            "YzU1N2Q1ZmRhMjc0M2VkN2EyNzkyNGQzYTRjMjY3MzIxZTAyNmFlMzY1YWI5NzhmOTU1ZTczMGNm" +
            "ODdjMzUyNzk2ZDk4MTdiZTJlZWZiY2EzNmYwZTlkMWIzZGE1N2QxMjk0NmJiNmQxYTc1ZWM0N2Jj" +
            "NmEwYzIyNDYyYWM5MjAxOWU2MmYwMDMwNmE5ZGRmMDUwZDBlYmI2MGVjYTA1ZWM0MGNvbS52cG4u" +
            "djJib3g=");

        protected override string C2ApiKey => Encoding.ASCII.FromBase64String("ODRlMDY4MmQtZmRkZC00NTA5LTlmOGYtZjBiMWI1MjU1NWNk");
    }

    public sealed class AddySq : AddyBase<AddySq.Parser>
    {
        public sealed class Parser : AddyParserBase<Parser>
        {
            protected override byte[] IdKey => ("q9BiIrTQMlF2ydiUFyCeNA==").FromBase64String();
            protected override byte[] IdIv => ("iGJJlhD3/AiUVZe5j+WXpQ==").FromBase64String();
        }
        public override string SampleSource => "aHR0cHM6Ly9wbGF5Lmdvb2dsZS5jb20vc3RvcmUvYXBwcy9kZXRhaWxzP2lkPWNvbS5zcXVpZHgudnBuYXBw";

        public override string SampleVersion => "1.0";

        protected override string C2RepoName => Encoding.ASCII.FromBase64String("c3F1aWR2cG4=");

        protected override string OuterSeed => Encoding.ASCII.FromBase64String(
            "MzA4MjA1ODkzMDgyMDM3MWEwMDMwMjAxMDIwMjE1MDA5NjY0M2NmMDc0YjQwOGZhYmZkYjAzYWQ0" +
            "YjI3NzFhNWQ5OTQ1NjVjMzAwZDA2MDkyYTg2NDg4NmY3MGQwMTAxMGIwNTAwMzA3NDMxMGIzMDA5" +
            "MDYwMzYwMDQwNjEzMDI1NTUzMzExMzMwMTEwNjAzNTUwNDA4MTMwYTQzNjE2YzY5NjY2ZjcyNmU2" +
            "OTYxMzExNjMwMTQwNjA3NDYwNDA3MTMwZDRkNmY3NTZlNzQ2MTY5NmUyMDU2Njk2NTc3MzExNDMw" +
            "MTIwNjAzNTUwNDBhMTMwYjQ3NmY2ZjY3NmM2NTIwNDk2ZTYzMmUzMTEwMzAwZTA2MDM1NTA0MGIx" +
            "MzA3NDE2ZTY0NzI2ZjY5NjQzMTEwMzAwZTA2MDM1NTA0MDMxMzA3NDE2ZTY0NzI2ZjY5NjQzMDIw" +
            "MTcwZDMyMzMzMDM1MzMzMTMwMzczMzM4MzUzNTVhMTgwZjMyMzAzNTMzMzAzNTMzMzEzMDM3MzMz" +
            "ODM1MzU1YTMwNzQzMTBiMzAwOTA2MDM1NTA0MDYxMzAyNTU1MzMxMTMzMDExMDYwMzU1MDQwODEz" +
            "MGE0MzYxNmM2OTY2NmY3MjZlNjk2MTMxMTYzMDE0MDYwMzU1MDQwNzEzMGQxYTJmNzU2ZTc0NjE2" +
            "OTZlMjA1NjY5NjU3NzMxMTQzMDEyMDYwMzU1MDQwYTEzMGI0NzZmNmY2NzZjNjUyMDQ5NmU2MzJl" +
            "MzExMDMwMGUwNjAzNTUwNDBiMTMwNzQxNmU2NDcyNmY2OTY0MzExMDMwMGUwNjAzNTUwNDAzMTMw" +
            "NzQxNmU2NDcyNmY2OTY0MzA4MjAyMjIzMDBkMDYwOTJhODY0ODg2ZjcwZDAxMDEwMTA1MDAwMzgy" +
            "MDIwZjAwMzA4MjAyMGEwMjgyMDIwMTAwYTEwNzBlMzUzYzEyMmM5YzRjZTgzZjRhMzk2OTMxYmM0" +
            "OTRjNzA2YTA5ZjY1YjA2MWEzNWRiZWEyZGY1NDQ1ZWYwOTJlNmIxZjM0MTgyYTc0YmY0ZjllYTk2" +
            "ZTAyYWE0ZTUwMmIwM2ExZWEwMzU1MGFjYWFmOTI2NTdkOTU2ZDhjYTU5NWZhNjZjNzQ4NjhkOWEy" +
            "OTg2ZGU3MzI3NmQ5N2Y3NzIxODIyZjU2NzQwMGEzNDQxZjNiMWZmNTM3OTZmODY1OWY0ODllYjYw" +
            "ZGMzY2UyMWRhY2M2N2I3YjE2NzE1ZGEwNWYwOWVhNTEzODc2ODU5MGQ5MDA4NjhiZDk3Yjc5NGNl" +
            "OTA5ZjE2YWU2ZjBkZjE4NmM0YWU2OTNiNzFlY2Y0YmExMTllODMxMjQ2NzYwNWUyZDc1OWY0OWNl" +
            "NTdiNjhkY2EzOTBiNTdmMmFkNzQ5NjZiMDAzNzNmZjVkMWNjOTlkZmY5Y2RiZTAxNWU5YmUyYzY3" +
            "NDYwZjVkMWI5MWY2ZGMwY2IwYTQzZWM2MDI5NmRlZDYxMGNhYTI1Y2JmYWRmOGNmYzVlMGIyOTcy" +
            "NmMyYWEyYzc5N2FlNjZiOTY1NGMyNmI5NTE1ODNiZjZiOWZhYzg3MWQ2ODcwNjdlMjNjZmIwMDJm" +
            "MDBhNGNlMWFiOTVjM2MwYWJhNjYyN2VjYjUzMTc2NWRmZTIwMWJiNjA4ODUzYzNlNDc1MjcwNTBj" +
            "ZTBjYzg0MmQzN2RlODNkMGQ3YWYzYjBiYzlmNzY4OGNkNDEzOTYyYjJjN2Q1Y2UyMjI3NDljNmJk" +
            "Mjc1NGRmMTJiMjBhMTM0NzAyZTFmOTcyZjJiYWI4NWZmZGU1NzBjN2IxOGRkNDA3YjYwM2QyNDE0" +
            "ODM4YjRhZjYyN2Y1NWFkZTc2MzA5NjVjYjdiMGNiZTM2MWM1ZGJmMzA3ZDE0ZWRjMTFmYmFlZDE3" +
            "ODY2ZDRmMmYxZTYxNTU4OTYyZDA4NmMzYTY0NmZjNzkzMWFiY2Y2NTM5YWRjOTg5OTMwMmNjOWZm" +
            "NmM4NGM2NDNiYmI3MTk5MDdjOTNmYmE3MTk5MGY2ZTU3YTJhYzRlZDVmNDk3YjRmYjE4ZjIwMDQ2" +
            "ZmQxMDg5ZjJiODAwNTY1ZmYwZDhiZDAwZDg5ZTYxNmVhOTk5Y2FjY2E5ZDc3ZmVlNGM4NDcyNzhm" +
            "NWUwMzI0NTg4YjMyOTNhNTEzNWEwYmE3Mjg3ZmQ3ODlkMzI3ODJmYWQ3ZDdiYjFiZTZkYzIxOTcz" +
            "NjBlOGNmNzEwNGZiYjI1Zjc1NjBiZDBjZjYyNWQzZDQyYWNhMTA4ZTUzZDZmYjdiOGU3NTQyY2Uy" +
            "YTA4ZDM3Zjk0MTgzNTE2ODZiZGNhYjAyMDMwMTAwMDFhMzEwMzAwZTMwMGMwNjAzNTUxZDEzMDQw" +
            "NTMwMDMwMTAxZmYzMDBkMDYwOTJhODY0ODg2ZjcwZDAxMDEwYjA1MDAwMzgyMDIwMTAwMDMyM2I1" +
            "MjAwYjhiNzFmMjExNWRjMzYxOWQ3MjM1ZTE0NWQwNjliNmVmNTQwMGVlNDFlYWI1NTEwZmVjNTNi" +
            "NDU4ZmY2NTY1MTFjYjg0ZmQ2N2VjMDg2MmE1YzRmMjVkZWNhYWE5ZDRlOWZmMGM5OWU3NjllODdm" +
            "Mjg5N2JjYjA3ZWJiZDNmZDMzMWRmMGYyZGFmMTE1NGExMDcwZTdlMmM3OTNmOTI5OGRhYzI2YjI1" +
            "NThmYTk2MTI3N2RiZjMzZTMyZjI4ZTJkMmEzODliNDQ1NzRlMjNhZmM0ODU3MzFhOWE2ZGNmMzUz" +
            "YTVhMzIyZDdiMjJjYmEyNWQ0MzgxNzZhMmM1MGVhOTNjZjU1NjEwYjE4MGU2NTk2YzJjN2IzNzZh" +
            "MzkxYjczZDIyY2Y2NDhiOWFhZTQ2OWY5NzlhZjI5NTA3OWU5OWIxNDUzYjI2YTBkZDM1MjJlZmVi" +
            "ODA3YjY0YTI0ZWExOWQ3NWRlMTcwMjM3OWVmZWZlMDNmZDNmNjgxYjA1Mzg5MmUzNGJiYmY0NDlh" +
            "ZDFmOTk2MDRhNjdlMTkxNDY4NTIyMGQ3MTU4MDNiYWRjOTg5N2U5Y2E0MDE2Y2JkNjMyNTYxOTA3" +
            "YjE3ZWZkNjFiMjY4ZThiNmRkN2JkZWMxMzdhYTg3MzUwYzg4YzU3OTBkNThmMjlkZjFiYzcwNGI1" +
            "NTgwNTUyNTU5MmExZWY3NmIzNjE1ZWMyNjA1OGNiOWIzYWYzMDJmODFhZDhkZDgyNDQ0YTg5ODBi" +
            "OTkyYThkMjlkNTJhMTEzZTRmMDQxMGYwMmM0NjcwN2ZkZGYzZDcwN2Q0M2RlNWUyMmI4NWQ1Nzhj" +
            "YWFhNjJiNGE3M2MzNGI0YzI2MWQ5YTZjODc5ZjY3MzNiNTJhOWE2NjgwODc5NTY4MWZhODgyZTMw" +
            "MDM0Mjc1N2NjYTI0OWNhZTM2YzlmY2M1NTJmNWFjYjQwMjhjNjJmMzMzZjMxMWFkNzQ1NTJhMTIy" +
            "YWQ2NmQxY2ZiMGM0OGEyYTcwZGQzNzk5Y2NiOWExMzc4ZmE0YTljMzdlMDRhM2UxZWYwN2YxODU1" +
            "Y2M1ODFmMTgyMDAyMTdlNWRmMmRhZjFmNDFjNzllMTIxNDIyMTNlMTY5ZTIyMjg5ZjcyOGY3MTcw" +
            "MThlNzhhNTAwODcxYTI3ZmJiZTZhODk3ZDc5ZjU2OWRiOTZmNjk5ODAyMDI5YmQ0OWU3MDVmZWQ0" +
            "MWM5MGE5ZTFiZjEwYTFhYmIwNTQzNzY2ZDk2NjY4NTA4ZjllZmEzODFlODAzZTc5ODUwOTFjZGQ2" +
            "ZTJmNDllMWIwYjM4OWM3ZmRmZDkzMzM0ZTM2MTUzOTQ4OGNmNDk4YWUxYTg3NDQzNmNvbS5zcXVp" +
            "ZHgudnBuYXBw");

        protected override string C2ApiKey => Encoding.ASCII.FromBase64String("ZmIxYzEzNmUtOGQyMy00OGMzLTliMWMtOGFiYWJlYWE0MWFh");
    }
}
