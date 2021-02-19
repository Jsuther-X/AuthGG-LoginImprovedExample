using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Auth.GG_Winform_Example
{
    internal class App
    {
        public static string Error = null;
        public static Dictionary<string, string> Variables = new Dictionary<string, string>();

        public static string GrabVariable(string name)
        {
            try
            {
                if (User.ID != null || User.HWID != null || User.IP != null || !Constants.Breached)
                    return Variables[name];

                Constants.Breached = true;
                return "User is not logged in, possible breach detected!";
            }
            catch
            {
                return "N/A";
            }
        }
    }

    internal class Constants
    {
        public static bool Breached;

        public static bool Started;

        public static string IV;

        public static string Key;

        public static string ApiUrl = "https://api.auth.gg/csharp/";

        public static bool Initialized;

        public static Random random = new Random();
        public static string Token { get; set; }

        public static string Date { get; set; }

        public static string APIENCRYPTKEY { get; set; }

        public static string APIENCRYPTSALT { get; set; }

        public static string RandomString(int length)
        {
            return new string(Enumerable
                .Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static string HWID()
        {
            return WindowsIdentity.GetCurrent().User.Value;
        }
    }

    internal class User
    {
        public static string ID { get; set; }

        public static string Username { get; set; }

        public static string Password { get; set; }

        public static string Email { get; set; }

        public static string HWID { get; set; }

        public static string IP { get; set; }

        public static string UserVariable { get; set; }

        public static string Rank { get; set; }

        public static string Expiry { get; set; }

        public static string LastLogin { get; set; }

        public static string RegisterDate { get; set; }
    }

    internal class ApplicationSettings
    {
        public static bool Status { get; set; }

        public static bool DeveloperMode { get; set; }

        public static string Hash { get; set; }

        public static string Version { get; set; }

        public static string Update_Link { get; set; }

        public static bool Freemode { get; set; }

        public static bool Login { get; set; }

        public static string Name { get; set; }

        public static bool Register { get; set; }
    }

    internal class OnProgramStart
    {
        public static string AID;

        public static string Secret;

        public static string Version;

        public static string Name;

        public static string Salt = null;

        public static void Initialize(string name, string aid, string secret, string version)
        {
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(aid) ||
                string.IsNullOrWhiteSpace(secret) ||
                string.IsNullOrWhiteSpace(version)) Process.GetCurrentProcess().Kill();
            AID = aid;
            Secret = secret;
            Version = version;
            Name = name;
            string[] response = { };
            using (var wc = new WebClient())
            {
                try
                {
                    wc.Proxy = null;
                    Security.Start();
                    response = Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl,
                        new NameValueCollection
                        {
                            ["token"] = Encryption.EncryptService(Constants.Token),
                            ["timestamp"] = Encryption.EncryptService(DateTime.Now.ToString()),
                            ["aid"] = Encryption.APIService(AID),
                            ["session_id"] = Constants.IV,
                            ["api_id"] = Constants.APIENCRYPTSALT,
                            ["api_key"] = Constants.APIENCRYPTKEY,
                            ["session_key"] = Constants.Key,
                            ["secret"] = Encryption.APIService(Secret),
                            ["type"] = Encryption.APIService("start")
                        }))).Split("|".ToCharArray());
                    if (Security.MaliciousCheck(response[1])) Process.GetCurrentProcess().Kill();
                    if (Constants.Breached) Process.GetCurrentProcess().Kill();
                    if (response[0] != Constants.Token) Process.GetCurrentProcess().Kill();
                    switch (response[2])
                    {
                        case "success":
                            Constants.Initialized = true;
                            if (response[3] == "Enabled")
                                ApplicationSettings.Status = true;
                            if (response[4] == "Enabled")
                                ApplicationSettings.DeveloperMode = true;
                            ApplicationSettings.Hash = response[5];
                            ApplicationSettings.Version = response[6];
                            ApplicationSettings.Update_Link = response[7];
                            if (response[8] == "Enabled")
                                ApplicationSettings.Freemode = true;
                            if (response[9] == "Enabled")
                                ApplicationSettings.Login = true;
                            ApplicationSettings.Name = response[10];
                            if (response[11] == "Enabled")
                                ApplicationSettings.Register = true;
                            if (ApplicationSettings.DeveloperMode)
                            {
                                File.Create(Environment.CurrentDirectory + "/integrity.log").Close();
                                var hash = Security.Integrity(Process.GetCurrentProcess().MainModule.FileName);
                                File.WriteAllText(Environment.CurrentDirectory + "/integrity.log", hash);
                            }
                            else
                            {
                                if (response[12] == "Enabled")
                                    if (ApplicationSettings.Hash !=
                                        Security.Integrity(Process.GetCurrentProcess().MainModule.FileName))
                                        Process.GetCurrentProcess().Kill();
                                if (ApplicationSettings.Version != Version)
                                {
                                    Process.Start(ApplicationSettings.Update_Link);
                                    Process.GetCurrentProcess().Kill();
                                }
                            }

                            if (ApplicationSettings.Status == false) Process.GetCurrentProcess().Kill();
                            break;
                        case "binderror":
                            Process.GetCurrentProcess().Kill();
                            return;
                        case "banned":
                            Process.GetCurrentProcess().Kill();
                            return;
                    }

                    Security.End();
                }
                catch (Exception ex)
                {
                    Process.GetCurrentProcess().Kill();
                }
            }
        }
    }

    internal class API
    {
        public static void Log(string username, string action)
        {
            if (!Constants.Initialized) Process.GetCurrentProcess().Kill();
            if (string.IsNullOrWhiteSpace(action)) Process.GetCurrentProcess().Kill();
            string[] response = { };
            using (var wc = new WebClient())
            {
                try
                {
                    Security.Start();
                    wc.Proxy = null;
                    response = Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl,
                        new NameValueCollection
                        {
                            ["token"] = Encryption.EncryptService(Constants.Token),
                            ["aid"] = Encryption.APIService(OnProgramStart.AID),
                            ["username"] = Encryption.APIService(username),
                            ["pcuser"] = Encryption.APIService(Environment.UserName),
                            ["session_id"] = Constants.IV,
                            ["api_id"] = Constants.APIENCRYPTSALT,
                            ["api_key"] = Constants.APIENCRYPTKEY,
                            ["data"] = Encryption.APIService(action),
                            ["session_key"] = Constants.Key,
                            ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                            ["type"] = Encryption.APIService("log")
                        }))).Split("|".ToCharArray());
                    Security.End();
                }
                catch (Exception ex)
                {
                    Process.GetCurrentProcess().Kill();
                }
            }
        }

        public static bool AIO(string AIO)
        {
            if (AIOLogin(AIO)) return true;

            if (AIORegister(AIO))
                return true;
            return false;
        }

        public static bool AIOLogin(string AIO)
        {
            if (!Constants.Initialized) Process.GetCurrentProcess().Kill();
            if (string.IsNullOrWhiteSpace(AIO)) Process.GetCurrentProcess().Kill();
            string[] response = { };
            using (var wc = new WebClient())
            {
                try
                {
                    Security.Start();
                    wc.Proxy = null;
                    response = Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl,
                        new NameValueCollection
                        {
                            ["token"] = Encryption.EncryptService(Constants.Token),
                            ["timestamp"] = Encryption.EncryptService(DateTime.Now.ToString()),
                            ["aid"] = Encryption.APIService(OnProgramStart.AID),
                            ["session_id"] = Constants.IV,
                            ["api_id"] = Constants.APIENCRYPTSALT,
                            ["api_key"] = Constants.APIENCRYPTKEY,
                            ["username"] = Encryption.APIService(AIO),
                            ["password"] = Encryption.APIService(AIO),
                            ["hwid"] = Encryption.APIService(Constants.HWID()),
                            ["session_key"] = Constants.Key,
                            ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                            ["type"] = Encryption.APIService("login")
                        }))).Split("|".ToCharArray());
                    if (response[0] != Constants.Token) Process.GetCurrentProcess().Kill();
                    if (Security.MaliciousCheck(response[1])) Process.GetCurrentProcess().Kill();
                    if (Constants.Breached) Process.GetCurrentProcess().Kill();
                    switch (response[2])
                    {
                        case "success":
                            Security.End();
                            User.ID = response[3];
                            User.Username = response[4];
                            User.Password = response[5];
                            User.Email = response[6];
                            User.HWID = response[7];
                            User.UserVariable = response[8];
                            User.Rank = response[9];
                            User.IP = response[10];
                            User.Expiry = response[11];
                            User.LastLogin = response[12];
                            User.RegisterDate = response[13];
                            var Variables = response[14];
                            foreach (var var in Variables.Split('~'))
                            {
                                var items = var.Split('^');
                                try
                                {
                                    App.Variables.Add(items[0], items[1]);
                                }
                                catch
                                {
                                    //If some are null or not loaded, just ignore.
                                    //Error will be shown when loading the variable anyways
                                }
                            }

                            return true;
                        case "invalid_details":
                            Security.End();
                            return false;
                        case "time_expired":
                            Security.End();
                            return false;
                        case "hwid_updated":
                            Security.End();
                            return false;
                        case "invalid_hwid":
                            Security.End();
                            return false;
                    }
                }
                catch (Exception ex)
                {
                    Security.End();
                    Process.GetCurrentProcess().Kill();
                }

                return false;
            }
        }

        public static bool AIORegister(string AIO)
        {
            if (!Constants.Initialized)
            {
                Security.End();
                Process.GetCurrentProcess().Kill();
            }

            if (string.IsNullOrWhiteSpace(AIO)) Process.GetCurrentProcess().Kill();
            string[] response = { };
            using (var wc = new WebClient())
            {
                try
                {
                    Security.Start();
                    wc.Proxy = null;

                    response = Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl,
                        new NameValueCollection
                        {
                            ["token"] = Encryption.EncryptService(Constants.Token),
                            ["timestamp"] = Encryption.EncryptService(DateTime.Now.ToString()),
                            ["aid"] = Encryption.APIService(OnProgramStart.AID),
                            ["session_id"] = Constants.IV,
                            ["api_id"] = Constants.APIENCRYPTSALT,
                            ["api_key"] = Constants.APIENCRYPTKEY,
                            ["session_key"] = Constants.Key,
                            ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                            ["type"] = Encryption.APIService("register"),
                            ["username"] = Encryption.APIService(AIO),
                            ["password"] = Encryption.APIService(AIO),
                            ["email"] = Encryption.APIService(AIO),
                            ["license"] = Encryption.APIService(AIO),
                            ["hwid"] = Encryption.APIService(Constants.HWID())
                        }))).Split("|".ToCharArray());
                    if (response[0] != Constants.Token)
                    {
                        Security.End();
                        Process.GetCurrentProcess().Kill();
                    }

                    if (Security.MaliciousCheck(response[1])) Process.GetCurrentProcess().Kill();
                    if (Constants.Breached) Process.GetCurrentProcess().Kill();
                    Security.End();
                    switch (response[2])
                    {
                        case "success":
                            return true;
                        case "error":
                            return false;
                    }
                }
                catch (Exception ex)
                {
                    Process.GetCurrentProcess().Kill();
                }

                return false;
            }
        }

        public static bool Login(string username, string password)
        {
            if (!Constants.Initialized) Process.GetCurrentProcess().Kill();
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                Process.GetCurrentProcess().Kill();
            string[] response = { };
            using (var wc = new WebClient())
            {
                try
                {
                    Security.Start();
                    wc.Proxy = null;
                    response = Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl,
                        new NameValueCollection
                        {
                            ["token"] = Encryption.EncryptService(Constants.Token),
                            ["timestamp"] = Encryption.EncryptService(DateTime.Now.ToString()),
                            ["aid"] = Encryption.APIService(OnProgramStart.AID),
                            ["session_id"] = Constants.IV,
                            ["api_id"] = Constants.APIENCRYPTSALT,
                            ["api_key"] = Constants.APIENCRYPTKEY,
                            ["username"] = Encryption.APIService(username),
                            ["password"] = Encryption.APIService(password),
                            ["hwid"] = Encryption.APIService(Constants.HWID()),
                            ["session_key"] = Constants.Key,
                            ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                            ["type"] = Encryption.APIService("login")
                        }))).Split("|".ToCharArray());
                    if (response[0] != Constants.Token) Process.GetCurrentProcess().Kill();
                    if (Security.MaliciousCheck(response[1])) Process.GetCurrentProcess().Kill();
                    if (Constants.Breached) Process.GetCurrentProcess().Kill();
                    switch (response[2])
                    {
                        case "success":
                            User.ID = response[3];
                            User.Username = response[4];
                            User.Password = response[5];
                            User.Email = response[6];
                            User.HWID = response[7];
                            User.UserVariable = response[8];
                            User.Rank = response[9];
                            User.IP = response[10];
                            User.Expiry = response[11];
                            User.LastLogin = response[12];
                            User.RegisterDate = response[13];
                            var Variables = response[14];
                            foreach (var var in Variables.Split('~'))
                            {
                                var items = var.Split('^');
                                try
                                {
                                    App.Variables.Add(items[0], items[1]);
                                }
                                catch
                                {
                                    //If some are null or not loaded, just ignore.
                                    //Error will be shown when loading the variable anyways
                                }
                            }

                            Security.End();
                            return true;
                        case "invalid_details":
                            Security.End();
                            return false;
                        case "time_expired":
                            Security.End();
                            return false;
                        case "hwid_updated":
                            Security.End();
                            return false;
                        case "invalid_hwid":
                            Security.End();
                            return false;
                    }
                }
                catch (Exception ex)
                {
                    Security.End();
                    Process.GetCurrentProcess().Kill();
                }

                return false;
            }
        }

        public static bool Register(string username, string password, string email, string license)
        {
            if (!Constants.Initialized)
            {
                Security.End();
                Process.GetCurrentProcess().Kill();
            }

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password) ||
                string.IsNullOrWhiteSpace(email) ||
                string.IsNullOrWhiteSpace(license)) Process.GetCurrentProcess().Kill();
            string[] response = { };
            using (var wc = new WebClient())
            {
                try
                {
                    Security.Start();
                    wc.Proxy = null;

                    response = Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl,
                        new NameValueCollection
                        {
                            ["token"] = Encryption.EncryptService(Constants.Token),
                            ["timestamp"] = Encryption.EncryptService(DateTime.Now.ToString()),
                            ["aid"] = Encryption.APIService(OnProgramStart.AID),
                            ["session_id"] = Constants.IV,
                            ["api_id"] = Constants.APIENCRYPTSALT,
                            ["api_key"] = Constants.APIENCRYPTKEY,
                            ["session_key"] = Constants.Key,
                            ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                            ["type"] = Encryption.APIService("register"),
                            ["username"] = Encryption.APIService(username),
                            ["password"] = Encryption.APIService(password),
                            ["email"] = Encryption.APIService(email),
                            ["license"] = Encryption.APIService(license),
                            ["hwid"] = Encryption.APIService(Constants.HWID())
                        }))).Split("|".ToCharArray());
                    if (response[0] != Constants.Token)
                    {
                        Security.End();
                        Process.GetCurrentProcess().Kill();
                    }

                    if (Security.MaliciousCheck(response[1])) Process.GetCurrentProcess().Kill();
                    if (Constants.Breached) Process.GetCurrentProcess().Kill();
                    switch (response[2])
                    {
                        case "success":
                            Security.End();
                            return true;
                        case "invalid_license":
                            Security.End();
                            return false;
                        case "email_used":
                            Security.End();
                            return false;
                        case "invalid_username":
                            Security.End();
                            return false;
                    }
                }
                catch (Exception ex)
                {
                    Process.GetCurrentProcess().Kill();
                }

                return false;
            }
        }

        public static bool ExtendSubscription(string username, string password, string license)
        {
            if (!Constants.Initialized)
            {
                Security.End();
                Process.GetCurrentProcess().Kill();
            }

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password) ||
                string.IsNullOrWhiteSpace(license)) Process.GetCurrentProcess().Kill();
            string[] response = { };
            using (var wc = new WebClient())
            {
                try
                {
                    Security.Start();
                    wc.Proxy = null;
                    response = Encryption.DecryptService(Encoding.Default.GetString(wc.UploadValues(Constants.ApiUrl,
                        new NameValueCollection
                        {
                            ["token"] = Encryption.EncryptService(Constants.Token),
                            ["timestamp"] = Encryption.EncryptService(DateTime.Now.ToString()),
                            ["aid"] = Encryption.APIService(OnProgramStart.AID),
                            ["session_id"] = Constants.IV,
                            ["api_id"] = Constants.APIENCRYPTSALT,
                            ["api_key"] = Constants.APIENCRYPTKEY,
                            ["session_key"] = Constants.Key,
                            ["secret"] = Encryption.APIService(OnProgramStart.Secret),
                            ["type"] = Encryption.APIService("extend"),
                            ["username"] = Encryption.APIService(username),
                            ["password"] = Encryption.APIService(password),
                            ["license"] = Encryption.APIService(license)
                        }))).Split("|".ToCharArray());
                    if (response[0] != Constants.Token)
                    {
                        Security.End();
                        Process.GetCurrentProcess().Kill();
                    }

                    if (Security.MaliciousCheck(response[1])) Process.GetCurrentProcess().Kill();
                    if (Constants.Breached) Process.GetCurrentProcess().Kill();
                    switch (response[2])
                    {
                        case "success":
                            Security.End();
                            return true;
                        case "invalid_token":
                            Security.End();
                            return false;
                        case "invalid_details":
                            Security.End();
                            return false;
                    }
                }
                catch (Exception ex)
                {
                    Process.GetCurrentProcess().Kill();
                }

                return false;
            }
        }
    }

    internal class Security
    {
        private const string _key =
            "046EECD33E469E9E1958D6BEEDE0A71843202724A5758BD1723F6C340C5E98EDE06FF5C21B35F359C65B850744729B3AA999B0B6392DA69EDB278EB31DBCE85774";

        public static string Signature(string value)
        {
            using (var md5 = MD5.Create())
            {
                var input = Encoding.UTF8.GetBytes(value);
                var hash = md5.ComputeHash(input);
                return BitConverter.ToString(hash).Replace("-", "");
            }
        }

        private static string Session(int length)
        {
            var random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static string Obfuscate(int length)
        {
            var random = new Random();
            const string chars =
                "gd8JQ57nxXzLLMPrLylVhxoGnWGCFjO4knKTfRE6mVvdjug2NF/4aptAsZcdIGbAPmcx0O+ftU/KvMIjcfUnH3j+IMdhAW5OpoX3MrjQdf5AAP97tTB5g1wdDSAqKpq9gw06t3VaqMWZHKtPSuAXy0kkZRsc+DicpcY8E9+vWMHXa3jMdbPx4YES0p66GzhqLd/heA2zMvX8iWv4wK7S3QKIW/a9dD4ALZJpmcr9OOE=";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static void Start()
        {
            var drive = Path.GetPathRoot(Environment.SystemDirectory);
            if (Constants.Started)
            {
                Process.GetCurrentProcess().Kill();
            }
            else
            {
                using (var sr = new StreamReader($@"{drive}Windows\System32\drivers\etc\hosts"))
                {
                    var contents = sr.ReadToEnd();
                    if (contents.Contains("api.auth.gg"))
                    {
                        Constants.Breached = true;
                        Process.GetCurrentProcess().Kill();
                    }
                }

                var infoManager = new InfoManager();
                infoManager.StartListener();
                Constants.Token = Guid.NewGuid().ToString();
                ServicePointManager.ServerCertificateValidationCallback += PinPublicKey;
                Constants.APIENCRYPTKEY = Convert.ToBase64String(Encoding.Default.GetBytes(Session(32)));
                Constants.APIENCRYPTSALT = Convert.ToBase64String(Encoding.Default.GetBytes(Session(16)));
                Constants.IV = Convert.ToBase64String(Encoding.Default.GetBytes(Constants.RandomString(16)));
                Constants.Key = Convert.ToBase64String(Encoding.Default.GetBytes(Constants.RandomString(32)));
                Constants.Started = true;
            }
        }

        public static void End()
        {
            if (!Constants.Started)
            {
                Process.GetCurrentProcess().Kill();
            }
            else
            {
                Constants.Token = null;
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                Constants.APIENCRYPTKEY = null;
                Constants.APIENCRYPTSALT = null;
                Constants.IV = null;
                Constants.Key = null;
                Constants.Started = false;
            }
        }

        private static bool PinPublicKey(object sender, X509Certificate certificate, X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            return certificate != null && certificate.GetPublicKeyString() == _key;
        }

        public static string Integrity(string filename)
        {
            string result;
            using (var md = MD5.Create())
            {
                using (var fileStream = File.OpenRead(filename))
                {
                    var value = md.ComputeHash(fileStream);
                    result = BitConverter.ToString(value).Replace("-", "").ToLowerInvariant();
                }
            }

            return result;
        }

        public static bool MaliciousCheck(string date)
        {
            var dt1 = DateTime.Parse(date); //time sent
            var dt2 = DateTime.Now; //time received
            var d3 = dt1 - dt2;
            if (Convert.ToInt32(d3.Seconds.ToString().Replace("-", "")) >= 5 ||
                Convert.ToInt32(d3.Minutes.ToString().Replace("-", "")) >= 1)
            {
                Constants.Breached = true;
                return true;
            }

            return false;
        }
    }

    internal class Encryption
    {
        public static string APIService(string value)
        {
            var message = value;
            var password = Encoding.Default.GetString(Convert.FromBase64String(Constants.APIENCRYPTKEY));
            var mySHA256 = SHA256.Create();
            var key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(password));
            var iv = Encoding.ASCII.GetBytes(
                Encoding.Default.GetString(Convert.FromBase64String(Constants.APIENCRYPTSALT)));
            var encrypted = EncryptString(message, key, iv);
            return encrypted;
        }

        public static string EncryptService(string value)
        {
            var message = value;
            var password = Encoding.Default.GetString(Convert.FromBase64String(Constants.APIENCRYPTKEY));
            var mySHA256 = SHA256.Create();
            var key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(password));
            var iv = Encoding.ASCII.GetBytes(
                Encoding.Default.GetString(Convert.FromBase64String(Constants.APIENCRYPTSALT)));
            var encrypted = EncryptString(message, key, iv);
            var property = int.Parse(OnProgramStart.AID.Substring(0, 2));
            var final = encrypted + Security.Obfuscate(property);
            return final;
        }

        public static string DecryptService(string value)
        {
            var message = value;
            var password = Encoding.Default.GetString(Convert.FromBase64String(Constants.APIENCRYPTKEY));
            var mySHA256 = SHA256.Create();
            var key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(password));
            var iv = Encoding.ASCII.GetBytes(
                Encoding.Default.GetString(Convert.FromBase64String(Constants.APIENCRYPTSALT)));
            var decrypted = DecryptString(message, key, iv);
            return decrypted;
        }

        public static string EncryptString(string plainText, byte[] key, byte[] iv)
        {
            var encryptor = Aes.Create();
            encryptor.Mode = CipherMode.CBC;
            encryptor.Key = key;
            encryptor.IV = iv;
            var memoryStream = new MemoryStream();
            var aesEncryptor = encryptor.CreateEncryptor();
            var cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write);
            var plainBytes = Encoding.ASCII.GetBytes(plainText);
            cryptoStream.Write(plainBytes, 0, plainBytes.Length);
            cryptoStream.FlushFinalBlock();
            var cipherBytes = memoryStream.ToArray();
            memoryStream.Close();
            cryptoStream.Close();
            var cipherText = Convert.ToBase64String(cipherBytes, 0, cipherBytes.Length);
            return cipherText;
        }

        public static string DecryptString(string cipherText, byte[] key, byte[] iv)
        {
            var encryptor = Aes.Create();
            encryptor.Mode = CipherMode.CBC;
            encryptor.Key = key;
            encryptor.IV = iv;
            var memoryStream = new MemoryStream();
            var aesDecryptor = encryptor.CreateDecryptor();
            var cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write);
            var plainText = string.Empty;
            try
            {
                var cipherBytes = Convert.FromBase64String(cipherText);
                cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);
                cryptoStream.FlushFinalBlock();
                var plainBytes = memoryStream.ToArray();
                plainText = Encoding.ASCII.GetString(plainBytes, 0, plainBytes.Length);
            }
            finally
            {
                memoryStream.Close();
                cryptoStream.Close();
            }

            return plainText;
        }

        public static string Decode(string text)
        {
            text = text.Replace('_', '/').Replace('-', '+');
            switch (text.Length % 4)
            {
                case 2:
                    text += "==";
                    break;
                case 3:
                    text += "=";
                    break;
            }

            return Encoding.UTF8.GetString(Convert.FromBase64String(text));
        }
    }

    internal class InfoManager
    {
        private string lastGateway;
        private Timer timer;

        public InfoManager()
        {
            lastGateway = GetGatewayMAC();
        }

        public void StartListener()
        {
            timer = new Timer(_ => OnCallBack(), null, 5000, Timeout.Infinite);
        }

        private void OnCallBack()
        {
            timer.Dispose();
            if (!(GetGatewayMAC() == lastGateway))
            {
                Constants.Breached = true;
                Process.GetCurrentProcess().Kill();
            }
            else
            {
                lastGateway = GetGatewayMAC();
            }

            timer = new Timer(_ => OnCallBack(), null, 5000, Timeout.Infinite);
        }

        public static IPAddress GetDefaultGateway()
        {
            return NetworkInterface
                .GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties()?.GatewayAddresses)
                .Select(g => g?.Address)
                .Where(a => a != null)
                .FirstOrDefault();
        }

        private string GetArpTable()
        {
            var drive = Path.GetPathRoot(Environment.SystemDirectory);
            var start = new ProcessStartInfo();
            start.FileName = $@"{drive}Windows\System32\arp.exe";
            start.Arguments = "-a";
            start.UseShellExecute = false;
            start.RedirectStandardOutput = true;
            start.CreateNoWindow = true;

            using (var process = Process.Start(start))
            {
                using (var reader = process.StandardOutput)
                {
                    return reader.ReadToEnd();
                }
            }
        }

        private string GetGatewayMAC()
        {
            var routerIP = GetDefaultGateway().ToString();
            var regx = string.Format(@"({0} [\W]*) ([a-z0-9-]*)", routerIP);
            var regex = new Regex(regx);
            var matches = regex.Match(GetArpTable());
            return matches.Groups[2].ToString();
        }
    }
}