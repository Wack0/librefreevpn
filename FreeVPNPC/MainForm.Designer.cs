namespace FreeVPNPC
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.pictureBoxLogo = new System.Windows.Forms.PictureBox();
            this.checkBoxRisky = new System.Windows.Forms.CheckBox();
            this.groupBoxProtocol = new System.Windows.Forms.GroupBox();
            this.buttonProtocolSelectNone = new System.Windows.Forms.Button();
            this.buttonProtocolSelectAll = new System.Windows.Forms.Button();
            this.checkedListBoxProtocol = new System.Windows.Forms.CheckedListBox();
            this.groupBoxProvider = new System.Windows.Forms.GroupBox();
            this.buttonProviderSelectNone = new System.Windows.Forms.Button();
            this.buttonProviderSelectAll = new System.Windows.Forms.Button();
            this.checkedListBoxProvider = new System.Windows.Forms.CheckedListBox();
            this.buttonGet = new System.Windows.Forms.Button();
            this.labelDevelopedText = new System.Windows.Forms.Label();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBoxLogo)).BeginInit();
            this.groupBoxProtocol.SuspendLayout();
            this.groupBoxProvider.SuspendLayout();
            this.SuspendLayout();
            // 
            // pictureBoxLogo
            // 
            this.pictureBoxLogo.Location = new System.Drawing.Point(12, 12);
            this.pictureBoxLogo.Name = "pictureBoxLogo";
            this.pictureBoxLogo.Size = new System.Drawing.Size(567, 126);
            this.pictureBoxLogo.TabIndex = 0;
            this.pictureBoxLogo.TabStop = false;
            // 
            // checkBoxRisky
            // 
            this.checkBoxRisky.AutoSize = true;
            this.checkBoxRisky.Location = new System.Drawing.Point(13, 145);
            this.checkBoxRisky.Name = "checkBoxRisky";
            this.checkBoxRisky.Size = new System.Drawing.Size(216, 17);
            this.checkBoxRisky.TabIndex = 1;
            this.checkBoxRisky.Text = "Show providers that make risky requests";
            this.checkBoxRisky.UseVisualStyleBackColor = true;
            this.checkBoxRisky.CheckedChanged += new System.EventHandler(this.checkBoxRisky_CheckedChanged);
            // 
            // groupBoxProtocol
            // 
            this.groupBoxProtocol.Controls.Add(this.buttonProtocolSelectNone);
            this.groupBoxProtocol.Controls.Add(this.buttonProtocolSelectAll);
            this.groupBoxProtocol.Controls.Add(this.checkedListBoxProtocol);
            this.groupBoxProtocol.Location = new System.Drawing.Point(13, 169);
            this.groupBoxProtocol.Name = "groupBoxProtocol";
            this.groupBoxProtocol.Size = new System.Drawing.Size(261, 288);
            this.groupBoxProtocol.TabIndex = 2;
            this.groupBoxProtocol.TabStop = false;
            this.groupBoxProtocol.Text = "Protocol Selection";
            // 
            // buttonProtocolSelectNone
            // 
            this.buttonProtocolSelectNone.Location = new System.Drawing.Point(180, 256);
            this.buttonProtocolSelectNone.Name = "buttonProtocolSelectNone";
            this.buttonProtocolSelectNone.Size = new System.Drawing.Size(75, 23);
            this.buttonProtocolSelectNone.TabIndex = 4;
            this.buttonProtocolSelectNone.Text = "Select None";
            this.buttonProtocolSelectNone.UseVisualStyleBackColor = true;
            this.buttonProtocolSelectNone.Click += new System.EventHandler(this.buttonProtocolSelectNone_Click);
            // 
            // buttonProtocolSelectAll
            // 
            this.buttonProtocolSelectAll.Location = new System.Drawing.Point(7, 256);
            this.buttonProtocolSelectAll.Name = "buttonProtocolSelectAll";
            this.buttonProtocolSelectAll.Size = new System.Drawing.Size(75, 23);
            this.buttonProtocolSelectAll.TabIndex = 3;
            this.buttonProtocolSelectAll.Text = "Select All (&P)";
            this.buttonProtocolSelectAll.UseVisualStyleBackColor = true;
            this.buttonProtocolSelectAll.Click += new System.EventHandler(this.buttonProtocolSelectAll_Click);
            // 
            // checkedListBoxProtocol
            // 
            this.checkedListBoxProtocol.FormattingEnabled = true;
            this.checkedListBoxProtocol.Location = new System.Drawing.Point(7, 20);
            this.checkedListBoxProtocol.Name = "checkedListBoxProtocol";
            this.checkedListBoxProtocol.Size = new System.Drawing.Size(248, 229);
            this.checkedListBoxProtocol.TabIndex = 2;
            this.checkedListBoxProtocol.ItemCheck += new System.Windows.Forms.ItemCheckEventHandler(this.checkedListBoxProtocol_ItemCheck);
            // 
            // groupBoxProvider
            // 
            this.groupBoxProvider.Controls.Add(this.buttonProviderSelectNone);
            this.groupBoxProvider.Controls.Add(this.buttonProviderSelectAll);
            this.groupBoxProvider.Controls.Add(this.checkedListBoxProvider);
            this.groupBoxProvider.Location = new System.Drawing.Point(295, 169);
            this.groupBoxProvider.Name = "groupBoxProvider";
            this.groupBoxProvider.Size = new System.Drawing.Size(261, 288);
            this.groupBoxProvider.TabIndex = 3;
            this.groupBoxProvider.TabStop = false;
            this.groupBoxProvider.Text = "Provider Selection";
            // 
            // buttonProviderSelectNone
            // 
            this.buttonProviderSelectNone.Location = new System.Drawing.Point(180, 256);
            this.buttonProviderSelectNone.Name = "buttonProviderSelectNone";
            this.buttonProviderSelectNone.Size = new System.Drawing.Size(75, 23);
            this.buttonProviderSelectNone.TabIndex = 7;
            this.buttonProviderSelectNone.Text = "Select None";
            this.buttonProviderSelectNone.UseVisualStyleBackColor = true;
            this.buttonProviderSelectNone.Click += new System.EventHandler(this.buttonProviderSelectNone_Click);
            // 
            // buttonProviderSelectAll
            // 
            this.buttonProviderSelectAll.Location = new System.Drawing.Point(7, 256);
            this.buttonProviderSelectAll.Name = "buttonProviderSelectAll";
            this.buttonProviderSelectAll.Size = new System.Drawing.Size(75, 23);
            this.buttonProviderSelectAll.TabIndex = 6;
            this.buttonProviderSelectAll.Text = "&Select All";
            this.buttonProviderSelectAll.UseVisualStyleBackColor = true;
            this.buttonProviderSelectAll.Click += new System.EventHandler(this.buttonProviderSelectAll_Click);
            // 
            // checkedListBoxProvider
            // 
            this.checkedListBoxProvider.FormattingEnabled = true;
            this.checkedListBoxProvider.Location = new System.Drawing.Point(7, 20);
            this.checkedListBoxProvider.Name = "checkedListBoxProvider";
            this.checkedListBoxProvider.Size = new System.Drawing.Size(248, 229);
            this.checkedListBoxProvider.TabIndex = 5;
            // 
            // buttonGet
            // 
            this.buttonGet.Location = new System.Drawing.Point(248, 463);
            this.buttonGet.Name = "buttonGet";
            this.buttonGet.Size = new System.Drawing.Size(75, 23);
            this.buttonGet.TabIndex = 8;
            this.buttonGet.Text = "&Get Configs";
            this.buttonGet.UseVisualStyleBackColor = true;
            this.buttonGet.Click += new System.EventHandler(this.buttonGet_Click);
            // 
            // labelDevelopedText
            // 
            this.labelDevelopedText.AutoSize = true;
            this.labelDevelopedText.Location = new System.Drawing.Point(12, 493);
            this.labelDevelopedText.Name = "labelDevelopedText";
            this.labelDevelopedText.Size = new System.Drawing.Size(217, 13);
            this.labelDevelopedText.TabIndex = 9;
            this.labelDevelopedText.Text = "Developed as part of the librefreevpn project";
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(591, 515);
            this.Controls.Add(this.labelDevelopedText);
            this.Controls.Add(this.buttonGet);
            this.Controls.Add(this.groupBoxProvider);
            this.Controls.Add(this.groupBoxProtocol);
            this.Controls.Add(this.checkBoxRisky);
            this.Controls.Add(this.pictureBoxLogo);
            this.Name = "MainForm";
            this.Text = "FreeVPNPC";
            this.Load += new System.EventHandler(this.MainForm_Load);
            ((System.ComponentModel.ISupportInitialize)(this.pictureBoxLogo)).EndInit();
            this.groupBoxProtocol.ResumeLayout(false);
            this.groupBoxProvider.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.PictureBox pictureBoxLogo;
        private System.Windows.Forms.CheckBox checkBoxRisky;
        private System.Windows.Forms.GroupBox groupBoxProtocol;
        private System.Windows.Forms.Button buttonProtocolSelectAll;
        private System.Windows.Forms.CheckedListBox checkedListBoxProtocol;
        private System.Windows.Forms.Button buttonProtocolSelectNone;
        private System.Windows.Forms.GroupBox groupBoxProvider;
        private System.Windows.Forms.Button buttonProviderSelectNone;
        private System.Windows.Forms.Button buttonProviderSelectAll;
        private System.Windows.Forms.CheckedListBox checkedListBoxProvider;
        private System.Windows.Forms.Button buttonGet;
        private System.Windows.Forms.Label labelDevelopedText;
    }
}

