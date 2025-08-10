using LibFreeVPN.Servers;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LibFreeVPN.Providers
{
    // Android app, distributed outside of Play Store. SocksHttp fork. SSH + v2ray (v2ray can domain front through zoom)
    public sealed class ShAzsm : VPNProviderBase
    {
        private sealed class Parser : SocksHttpParser<Parser>
        {
            protected override string CountryNameKey => "FLAG";
            protected override string V2RayKey => "v2rayJson";
            protected override string ServerTypeKey => "sPais";

            // Instead of reimplementing the key derivation code, use the already derived key
            private static readonly byte[] s_AesKey =
            {
                0xf0, 0x00, 0x8d, 0xc9, 0x5b, 0x34, 0x67, 0xf7,
                0xa3, 0x55, 0x4c, 0x23, 0x69, 0xe8, 0x54, 0xd1,
                0x5c, 0x04, 0xd9, 0xd4, 0xb6, 0x5d, 0x8c, 0xbd,
                0xed, 0xee, 0xa6, 0x2f, 0x77, 0xfb, 0x22, 0xef
            };

            private static readonly byte[] s_AesIv = new byte[0x10]; // all-zero IV

            protected override string DecryptOuter(string ciphertext)
            {
                var cipherTextBytes = Convert.FromBase64String(ciphertext.Replace('-', '+').Replace('_', '/'));
                using (var aes = new AesManaged())
                {
                    aes.BlockSize = 128;
                    aes.KeySize = 256;
                    aes.Padding = PaddingMode.PKCS7;
                    using (var dec = aes.CreateDecryptor(s_AesKey, s_AesIv))
                    {
                        return Encoding.UTF8.GetString(dec.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length));
                    }
                }
            }
        }

        public override string SampleSource => "aHR0cHM6Ly93d3cubWVkaWFmaXJlLmNvbS9maWxlL2l2aGJsajhwdnNlbGtxcS9PcGVuVlBOKzIwNDguYXBrL2ZpbGU=";

        public override string SampleVersion => "1.1";

        public override bool RiskyRequests => false;

        public override bool HasProtocol(ServerProtocol protocol) =>
            protocol == ServerProtocol.SSH || protocol == ServerProtocol.V2Ray;

        private static readonly string s_RepoName = Encoding.ASCII.GetString(Convert.FromBase64String("U1VTSUUtMjAyMy9KU09O"));
        private static readonly string s_ConfigName = Encoding.ASCII.GetString(Convert.FromBase64String("ZmlsZXMvY29uZmlnLmpzb24="));


        protected override async Task<IEnumerable<IVPNServer>> GetServersAsyncImpl()
        {
            var httpClient = new HttpClient();
            // Get the single config file used here.
            var config = await httpClient.GetStringAsync(string.Format("https://raw.githubusercontent.com/{0}/main/{1}", s_RepoName, s_ConfigName));

            // And try to parse it
            var extraRegistry = CreateExtraRegistry();
            return Parser.ParseConfig(config, extraRegistry);
        }
    }
}
