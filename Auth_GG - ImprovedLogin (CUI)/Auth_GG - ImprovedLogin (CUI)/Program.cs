using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Auth.GG_Winform_Example;

namespace Auth_GG___ImprovedLogin__CUI_
{
    class Program
    {
        public static string userN = "";
        public static string userP = "";

        static void Main(string[] args)
        {
  starting: OnProgramStart.Initialize("PROGRAM NAME", "AID", "SECRET", "VERSION");
            System.Console.Title = "[~] AuthGG [~] LoginExample [~] Created by SNØW#1999 [~]";
            ascii();
            Colorful.Console.WriteLine("");
            Colorful.Console.WriteLine("");
            Colorful.Console.WriteLine("");
            Colorful.Console.Write(" [", System.Drawing.Color.White);
            Colorful.Console.Write("1");
            Colorful.Console.Write("]", System.Drawing.Color.White);
            Colorful.Console.Write(" Login");
            Colorful.Console.WriteLine("");
            Colorful.Console.Write(" [", System.Drawing.Color.White);
            Colorful.Console.Write("2");
            Colorful.Console.Write("]", System.Drawing.Color.White);
            Colorful.Console.Write(" Register");
            Colorful.Console.WriteLine("");
            Colorful.Console.Write(" [", System.Drawing.Color.White);
            Colorful.Console.Write("3");
            Colorful.Console.Write("]", System.Drawing.Color.White);
            Colorful.Console.Write(" Support");
            Colorful.Console.WriteLine("");
            Colorful.Console.WriteLine("");
            Colorful.Console.Write("  > ");
            string inputIfNoInfo = Colorful.Console.ReadLine();

            if (inputIfNoInfo == "3")
            {
                Colorful.Console.Clear();
                ascii();
                Colorful.Console.WriteLine("");
                Colorful.Console.WriteLine("");
                Colorful.Console.Write(" [", System.Drawing.Color.White);
                Colorful.Console.Write("~");
                Colorful.Console.Write("]", System.Drawing.Color.White);
                Colorful.Console.Write(" If you have any login problems, your HWID needs to be resetted or you forgot your password, contact us on discord!");
                Colorful.Console.WriteLine("");
                Colorful.Console.WriteLine("");
                Colorful.Console.Write(" [", System.Drawing.Color.White);
                Colorful.Console.Write("~");
                Colorful.Console.Write("]", System.Drawing.Color.White);
                Colorful.Console.Write("Execute you´re discord link for example");
                Thread.Sleep(5000);
                Colorful.Console.Clear();
                goto starting;
            }

            if (inputIfNoInfo == "1")
            {
                try
                {
                    StreamReader siii = new StreamReader("login.xml");
                    userN = siii.ReadLine();
                    userP = siii.ReadLine();
                    siii.Close();

                    if (API.Login(userN, userP))
                    {
                        Colorful.Console.Clear();
                        ascii();
                        Colorful.Console.WriteLine("");
                        Colorful.Console.WriteLine("");
                        Colorful.Console.Write(" [", System.Drawing.Color.White);
                        Colorful.Console.Write("~");
                        Colorful.Console.Write("]", System.Drawing.Color.White);
                        Colorful.Console.Write(" Login Successfully!");
                        Thread.Sleep(3000);
                        Colorful.Console.Clear();
                    }
                    else
                    {
                        Colorful.Console.WriteLine("No valuable credentials found. Please type in your username & password into the login file or your credentials are wrong!");
                        Colorful.Console.ReadKey();
                    }

                }
                catch (System.IO.DirectoryNotFoundException ex)
                {
                    Colorful.Console.WriteLine(ex.ToString());
                    Colorful.Console.ReadKey();
                }
            }
            if (inputIfNoInfo == "2")
            {
                Colorful.Console.WriteLine("");
                Colorful.Console.Write(" [", System.Drawing.Color.White);
                Colorful.Console.Write("~");
                Colorful.Console.Write("]", System.Drawing.Color.White);
                Colorful.Console.Write(" Username: ");
                var username = Colorful.Console.ReadLine();
                Program.userN = username.ToString();
                Colorful.Console.WriteLine("");
                Colorful.Console.Write(" [", System.Drawing.Color.White);
                Colorful.Console.Write("~");
                Colorful.Console.Write("]", System.Drawing.Color.White);
                Colorful.Console.Write(" Password: ");
                var password = Colorful.Console.ReadLine();
                Program.userP = password.ToString();
                Colorful.Console.WriteLine("");
                Colorful.Console.Write(" [", System.Drawing.Color.White);
                Colorful.Console.Write("~");
                Colorful.Console.Write("]", System.Drawing.Color.White);
                Colorful.Console.Write(" Email: ");
                var email = Colorful.Console.ReadLine();
                Colorful.Console.WriteLine("");
                Colorful.Console.Write(" [", System.Drawing.Color.White);
                Colorful.Console.Write("~");
                Colorful.Console.Write("]", System.Drawing.Color.White);
                Colorful.Console.Write(" License: ");
                var license = Colorful.Console.ReadLine();
                Colorful.Console.Clear();
                try
                {
                    if (API.Register(username, password, email, license))
                    {
                        ascii();
                        Colorful.Console.WriteLine("");
                        Colorful.Console.WriteLine("");
                        Colorful.Console.Write(" [", System.Drawing.Color.White);
                        Colorful.Console.Write("~");
                        Colorful.Console.Write("]", System.Drawing.Color.White);
                        Colorful.Console.Write(" Registered - Credentials Saved");
                        Thread.Sleep(3000);
                        Colorful.Console.Clear();
                    }
                    var sw = new System.IO.StreamWriter("login.xml");
                    sw.Write(username + "\n" + password);
                    sw.Close();
                    ascii();
                    Colorful.Console.WriteLine("");
                    Colorful.Console.WriteLine("");
                    Colorful.Console.Write(" [", System.Drawing.Color.White);
                    Colorful.Console.Write("~");
                    Colorful.Console.Write("]", System.Drawing.Color.White);
                    Colorful.Console.WriteLine(" Success! - Restart the software to login.");
                    Thread.Sleep(3000);
                    Environment.Exit(0);

                }
                catch (System.IO.DirectoryNotFoundException ex)
                {
                    System.IO.Directory.CreateDirectory("login.xml");
                    var sw = new System.IO.StreamWriter("login.xml");
                    sw.Write(username + "\n" + password);
                    sw.Close();
                    Colorful.Console.Clear();
                    ascii();
                    Colorful.Console.WriteLine("");
                    Colorful.Console.WriteLine("");
                    Colorful.Console.WriteLine("Success! - Restart the software to login.");
                    Thread.Sleep(2000);
                    Environment.Exit(0);
                }

            }

            Colorful.Console.Clear();
            Colorful.Console.WriteLine("Code after successful login will be printed here.");
            Colorful.Console.ReadKey();

        }

        public static void ascii()
        {
            Colorful.Console.ForegroundColor = System.Drawing.Color.SkyBlue;
            Colorful.Console.WriteLine(@"");
            Colorful.Console.WriteLine(@"");
            Colorful.Console.WriteLine(@"              _   _      _____  _____ ", System.Drawing.Color.SkyBlue);
            Colorful.Console.WriteLine(@"             | | | |    / ____|/ ____|", System.Drawing.Color.SkyBlue);
            Colorful.Console.WriteLine(@"   __ _ _   _| |_| |__ | |  __| |  __ ", System.Drawing.Color.SkyBlue);
            Colorful.Console.WriteLine(@"  / _` | | | | __| '_ \| | |_ | | |_ |", System.Drawing.Color.SkyBlue);
            Colorful.Console.WriteLine(@" | (_| | |_| | |_| | | | |__| | |__| |", System.Drawing.Color.SkyBlue);
            Colorful.Console.WriteLine(@"  \__,_|\__,_|\__|_| |_|\_____|\_____|", System.Drawing.Color.SkyBlue);
            Colorful.Console.WriteLine(@"");
            Colorful.Console.WriteLine(@"");
        }
    }
}
