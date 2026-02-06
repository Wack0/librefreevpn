using LibFreeVPN;
using FreeVPNPC.Properties;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Drawing.Imaging;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FreeVPNPC
{

    public partial class MainForm : Form
    {
        private Bitmap m_LogoBitmap;
        private bool m_Initialised;
        private List<IVPNProvider> m_Providers = new List<IVPNProvider>();
        public MainForm()
        {
            InitializeComponent();
            // At runtime, convert logo bitmap colour from black to the actual window text colour.

            var bmp = Resources.freevpn_logo;
            m_LogoBitmap = new Bitmap(bmp);
            var replaceColour = SystemColors.WindowText;
            if (replaceColour != Color.Black)
            {
                if (m_LogoBitmap.PixelFormat != PixelFormat.Format32bppArgb)
                    m_LogoBitmap = m_LogoBitmap.Clone(new Rectangle(0, 0, bmp.Width, bmp.Height), PixelFormat.Format32bppArgb);
                using (var fast = new FastBitmap(m_LogoBitmap, ImageLockMode.ReadWrite))
                {
                    var bigEndian = !BitConverter.IsLittleEndian;
                    for (int y = 0; y < bmp.Height; y++)
                    {
                        for (int x = 0; x < fast.Width; x++)
                        {
                            var data = fast[x, y];
                            if (bigEndian)
                            {
                                if (data[0] != 0)
                                {
                                    data[1] = replaceColour.R;
                                    data[2] = replaceColour.G;
                                    data[3] = replaceColour.B;
                                }
                            }
                            else
                            {
                                if (data[3] != 0)
                                {
                                    data[2] = replaceColour.R;
                                    data[1] = replaceColour.G;
                                    data[0] = replaceColour.B;
                                }
                            }
                        }
                    }
                }
            }

            pictureBoxLogo.Image = m_LogoBitmap;
        }

        private void RefreshProviderList(ItemCheckEventArgs e)
        {
            List<ServerProtocol> protocols = new List<ServerProtocol>();
            bool allTicked = true;
            for (int i = 0; i < checkedListBoxProtocol.Items.Count; i++)
            {
                bool ticked = false;
                if (e != null && i == e.Index) ticked = e.NewValue == CheckState.Checked;
                else ticked = checkedListBoxProtocol.GetItemChecked(i);
                if (!ticked)
                {
                    allTicked = false;
                    continue;
                }
                protocols.Add((ServerProtocol)(i + 1));
            }

            m_Providers = VPNProviders.Providers.Where((p) =>
            {
                if (p.RiskyRequests && !checkBoxRisky.Checked) return false;
                if (allTicked) return true;
                return protocols.Any((prot) => p.HasProtocol(prot));
            }).OrderBy((p) => p.Name).ToList();

            checkedListBoxProvider.Items.Clear();
            for (int i = 0; i < m_Providers.Count; i++)
            {
                checkedListBoxProvider.Items.Add(m_Providers[i].Name);
                checkedListBoxProvider.SetItemChecked(i, true);
            }
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            var names = Enum.GetNames(typeof(ServerProtocol));
            for (int i = 1; i < names.Length; i++)
            {
                checkedListBoxProtocol.Items.Add(names[i]);
                checkedListBoxProtocol.SetItemChecked(i - 1, true);
            }
            m_Initialised = true;
            RefreshProviderList(null);
        }

        private void checkedListBoxProtocol_ItemCheck(object sender, ItemCheckEventArgs e)
        {
            if (!m_Initialised) return;
            RefreshProviderList(e);
        }

        private void checkBoxRisky_CheckedChanged(object sender, EventArgs e)
        {
            RefreshProviderList(null);
        }

        private void buttonProtocolSelectAll_Click(object sender, EventArgs e)
        {
            m_Initialised = false;
            for (int i = 0; i < checkedListBoxProtocol.Items.Count; i++)
                checkedListBoxProtocol.SetItemChecked(i, true);
            m_Initialised = true;
            RefreshProviderList(null);
        }

        private void buttonProtocolSelectNone_Click(object sender, EventArgs e)
        {
            m_Initialised = false;
            for (int i = 0; i < checkedListBoxProtocol.Items.Count; i++)
                checkedListBoxProtocol.SetItemChecked(i, false);
            m_Initialised = true;
            RefreshProviderList(null);
        }

        private void buttonProviderSelectAll_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < checkedListBoxProvider.Items.Count; i++)
                checkedListBoxProvider.SetItemChecked(i, true);
        }

        private void buttonProviderSelectNone_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < checkedListBoxProvider.Items.Count; i++)
                checkedListBoxProvider.SetItemChecked(i, false);
        }

        private async void buttonGet_Click(object sender, EventArgs e)
        {
            buttonGet.Enabled = false;
            var providers = m_Providers.Where((prov, index) => checkedListBoxProvider.GetItemChecked(index));
            var tasks = providers.Select((prov) => prov.GetServersAsync()).ToArray();
            await Task.WhenAll(tasks);

            var servers = tasks.SelectMany((t) => t.Result).ToList();
            buttonGet.Enabled = true;
            var cld = new ConfigListDialog(servers);
            cld.Show();

        }
    }

    public class FastBitmap : IDisposable
    {
        private Bitmap _bmp;
        private ImageLockMode _lockmode;
        private int _pixelLength;

        private Rectangle _rect;
        private BitmapData _data;
        private IntPtr _bufferPtr;

        public int Width { get => _bmp.Width; }
        public int Height { get => _bmp.Height; }
        public PixelFormat PixelFormat { get => _bmp.PixelFormat; }

        public FastBitmap(Bitmap bmp, ImageLockMode lockMode)
        {
            _bmp = bmp;
            _lockmode = lockMode;

            _pixelLength = Image.GetPixelFormatSize(bmp.PixelFormat) / 8;
            _rect = new Rectangle(0, 0, Width, Height);
            _data = bmp.LockBits(_rect, lockMode, PixelFormat);
            _bufferPtr = _data.Scan0;
        }

        public Span<byte> this[int x, int y]
        {
            get
            {
                var pixel = _bufferPtr + y * _data.Stride + x * _pixelLength;
                unsafe
                {
                    return new Span<byte>((byte*)pixel, _pixelLength);
                }
            }
            set
            {
                value.CopyTo(this[x, y]);
            }
        }

        public void Dispose()
        {
            _bmp.UnlockBits(_data);
        }
    }
}
