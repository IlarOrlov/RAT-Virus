using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace zprgopt
{
    internal class Program
    {
        static void Main(string[] args)
        {
            RegisterProgramOnStartup();

            while (true)
            {
                FindAndKillProgram(GetProcesses());
                Thread.Sleep(1000);
            }
        }

        static void FindAndKillProgram(List<string> names)
        {
            Process[] processes = Process.GetProcesses();

            foreach (Process process in processes)
            {
                foreach (string item in names)
                {
                    try { if (process.ProcessName.ToLower().Contains(item.ToLower())) process.Kill(); }
                    catch { return; }
                }
            }
        }

        static void RegisterProgramOnStartup()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                {
                    // Set the path of the executable to run on startup
                    key.SetValue("ApplicationBlocker", "\"" + Process.GetCurrentProcess().MainModule.FileName + "\"");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error registering the program on startup: " + ex.Message);
            }
        }

        static List<string> GetProcesses()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RADAR", true))
            {
                return key.GetValue("Processes").ToString().Split(',')?.ToList();
            }
        }
    }
}