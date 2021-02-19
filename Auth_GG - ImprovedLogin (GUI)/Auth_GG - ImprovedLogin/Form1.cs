using Auth.GG_Winform_Example;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Auth_GG___ImprovedLogin
{
    public partial class Form1 : Form
    {
        [DllImport("Gdi32.dll", EntryPoint = "CreateRoundRectRgn")]

        private static extern IntPtr CreateRoundRectRgn
(
int nLeftRect,
int nTopRect,
int RightRect,
int nBottomRect,
int nWidthEllipse,
int nHeightEllipse
);
        public Form1()
        {
            InitializeComponent();
            Region = System.Drawing.Region.FromHrgn(CreateRoundRectRgn(0, 0, Width, Height, 25, 25));
        }

        public void saveData()
        {
            RegistryKey registryKey = Registry.CurrentUser.CreateSubKey("YOURPROGRAMNAME");
            registryKey.SetValue("Username YOUREPROGRAMNAME", this.textboxUsername.Text);
            registryKey.SetValue("Password YOUREPROGRAMNAME", this.textboxPassword.Text);
            registryKey.Close();
        }

        public void requestData()
        {
            try
            {
                RegistryKey registryKey = Registry.CurrentUser.CreateSubKey("YOUREPROGRAMNAME"); 
                object value = registryKey.GetValue("Username YOUREPROGRAMNAME");
                object value2 = registryKey.GetValue("Password YOUREPROGRAMNAME");
                registryKey.Close();
                this.textboxUsername.Text = value.ToString();
                this.textboxPassword.Text = value2.ToString();
            }
            catch
            {
                //give error output if you want, it´s not necessary
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            requestData();
        }

        private void loginBtn_Click(object sender, EventArgs e)
        {
            if (API.Login(this.textboxUsername.Text, this.textboxPassword.Text))
            {
                saveData();
                //code you want to execute after login has been successfull
            }
        }
    }
}
