using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Security.Cryptography;
using System.Numerics;
using NAudio.Wave;

/*
 * Protocol
 * CODE:PARAM1,PARAM2,PARAM3
 * 
 * nothingblyat,SeaOfThieves,SoTGame,robloxplayerbeta,discord,VALORANT-Win64-Shipping,genshinimpact,javaw,minecraft,steam,epicgameslauncher,cs2,opera,chrome
 */

namespace Server
{
    internal class Server
    {
        private static List<TcpClient> clients = new List<TcpClient>();
        private static Thread processingClient = null;
        private static Thread cleaner = null;
        private static int processinClientIndex = -1;

        private static readonly string key = "0123456789ABCDEF0123456789ABCDEF";
        private static readonly string iv = "0123456789ABCDEF";

        private static int dataReadSize = 256;

        private static Dictionary<int, string> commands = new Dictionary<int, string>()
        {
            { 1, "1" },
            { 2, "80" },
            { 3, "15" },
            { 4, "96" },
            { 5, "22" },
            { 6, "78" },
            { 7, "12" },
            { 8, "13" },
            { 50, "69" },
            { 51, "72" },
            { 52, "97" },
            { 53, "98" },
            { 100, "666" },
            { 101, "6661" }
        };

        static void Main(string[] args)
        {
            int port = 6945;
            TcpListener server = null;
            
            try
            {
                server = new TcpListener(IPAddress.Any, port);
                server.Start();
                Console.WriteLine("Server started on {0}:{1}. Waiting for a connection...", GetLocalIPAddress(), port);

                cleaner = new Thread(ClientsCleaner);
                cleaner.Start();

                Thread clientsAccepter = new Thread(() => ClientsAccepter(server));
                clientsAccepter.Start();

                byte res = 0;
                while (true)
                {
                    if (processingClient == null && clients.Count > 0)
                    {
                        while (true)
                        {
                            Console.Clear();
                            Console.WriteLine("Choose client:");
                            lock (clients)
                            {
                                for (int i = 0; i < clients.Count; i++)
                                {
                                    if (i == processinClientIndex) Console.WriteLine($"client {i} - current");
                                    else Console.WriteLine($"client {i}");
                                }
                            }

                            byte.TryParse(Console.ReadLine(), out res);

                            lock (clients)
                            {
                                if (res < 0 || res >= clients.Count)
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine("There is no user with such an index");
                                    Console.ForegroundColor = ConsoleColor.White;
                                }
                                else break;
                            }
                        }

                        processinClientIndex = res;
                        lock (clients) processingClient = new Thread(() => HandleClient(clients[processinClientIndex]));
                        processingClient.Start();
                        processingClient.Join();
                    }
                    else if (clients.Count == 0)
                    {
                        Console.Clear();
                        Console.WriteLine("No Clients");
                        Thread.Sleep(2000);
                    }
                }
            }
            catch (SocketException ex)
            {
                Console.WriteLine("SocketException: {0}", ex.Message);
            }
            finally
            {
                if (server != null) server.Stop();
            }

            Console.WriteLine("Server stopped.");
        }

        static void HandleClient(TcpClient client)
        {
            int res = 0;

            NetworkStream stream = client.GetStream();

            while (true)
            {
                bool getMessage = true;
                PrintMenu();
                int.TryParse(Console.ReadLine(), out res);

                try
                {
                    Console.Clear();
                    ClearNetworkStream(stream);

                    if (res == 0) break;
                    else if (res > 0 && res <= 7)
                    {
                        // Send Message
                        string response = "";
                        commands.TryGetValue(res, out response);
                        response = EncryptString(response);
                        byte[] responseData = Encoding.ASCII.GetBytes(response);
                        stream.Write(responseData, 0, responseData.Length);
                        Console.WriteLine("Sent: {0}", DecryptString(response));
                    }
                    else if (res == 50)
                    {
                        Console.WriteLine("\nWrite processes names, to quit write 'stop'\nTo cancel write 'cancel'");
                        string processes = "";
                        string process = "";
                        bool cancel = false;

                        while (!cancel)
                        {
                            process = Console.ReadLine();

                            if (process == "stop") break;
                            if (process == "cancel") cancel = true;
                            if (processes == string.Empty) processes += process;
                            else processes += ',' + process;
                        }

                        if (!cancel)
                        {
                            string response = "69:" + processes;
                            response = EncryptString(response);
                            byte[] responseData = Encoding.ASCII.GetBytes(response);
                            stream.Write(responseData, 0, responseData.Length);
                            Console.WriteLine("Sent: {0}", DecryptString(response));
                        }
                        else Console.WriteLine("Canceled ;)");
                    }
                    else if (res == 51)
                    {
                        Console.WriteLine("\nWrite read size\nTo cancel write 'cancel'");
                        int readSize = 0;
                        string input = "";
                        bool cancel = false;
                        bool run = true;

                        do
                        {
                            input = Console.ReadLine();
                            if (input == "cancel") cancel = true;
                            if (int.TryParse(input, out readSize)) run = false;
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("You should enter a numeric value (512)");
                                Console.ForegroundColor = ConsoleColor.White;
                            }
                        } while (!cancel && run);

                        if (!cancel)
                        {
                            string response = "72:" + readSize;
                            response = EncryptString(response);
                            byte[] responseData = Encoding.ASCII.GetBytes(response);
                            stream.Write(responseData, 0, responseData.Length);
                            Console.WriteLine("Sent: {0}", DecryptString(response));
                        }
                        else Console.WriteLine("Canceled ;)");
                    }
                    else if (res == 52)
                    {
                        Console.WriteLine("\nSet Limit Start Time\nEnter the time (HH:mm format)\nTo cancel write 'cancel'\n");
                        TimeSpan time;
                        string input = "";
                        bool cancel = false;
                        bool run = true;

                        do
                        {
                            input = Console.ReadLine();
                            if (input == "cancel") cancel = true;
                            if (TimeSpan.TryParse(input, out time)) run = false;
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("Enter the time (HH:mm format)");
                                Console.ForegroundColor = ConsoleColor.White;
                            }
                        } while (!cancel && run);

                        if (!cancel)
                        {
                            string response = "97:" + input;
                            response = EncryptString(response);
                            byte[] responseData = Encoding.ASCII.GetBytes(response);
                            stream.Write(responseData, 0, responseData.Length);
                            Console.WriteLine("Sent: {0}", DecryptString(response));
                        }
                        else Console.WriteLine("Canceled ;)");
                    }
                    else if (res == 53)
                    {
                        Console.WriteLine("\nSet Limit End Time\nEnter the time (HH:mm format)\nTo cancel write 'cancel'\n");
                        TimeSpan time;
                        string input = "";
                        bool cancel = false;
                        bool run = true;

                        do
                        {
                            input = Console.ReadLine();
                            if (input == "cancel") cancel = true;
                            if (TimeSpan.TryParse(input, out time)) run = false;
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("Enter the time (HH:mm format)");
                                Console.ForegroundColor = ConsoleColor.White;
                            }
                        } while (!cancel && run);

                        if (!cancel)
                        {
                            string response = "98:" + input;
                            response = EncryptString(response);
                            byte[] responseData = Encoding.ASCII.GetBytes(response);
                            stream.Write(responseData, 0, responseData.Length);
                            Console.WriteLine("Sent: {0}", DecryptString(response));
                        }
                        else Console.WriteLine("Canceled ;)");
                    }
                    else if (res == 8)
                    {
                        Console.WriteLine("\nSet Holiday\n1 - True\n0 - False\nTo cancel write 'cancel'\n");
                        string input = "";
                        bool cancel = false;
                        bool run = true;

                        do
                        {
                            input = Console.ReadLine();
                            if (input == "cancel") cancel = true;
                            if (input != "1" || input != "0") run = false;
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("1 - True\n0 - False");
                                Console.ForegroundColor = ConsoleColor.White;
                            }
                        } while (!cancel && run);

                        if (!cancel)
                        {
                            string response = "13:" + input;
                            response = EncryptString(response);
                            byte[] responseData = Encoding.ASCII.GetBytes(response);
                            stream.Write(responseData, 0, responseData.Length);
                            Console.WriteLine("Sent: {0}", DecryptString(response));
                        }
                        else Console.WriteLine("Canceled ;)");
                    }
                    else if (res == 100)
                    {
                        CancellationTokenSource cts = new CancellationTokenSource();
                        CancellationToken token = cts.Token;

                        // Create a thread to listen for stop command
                        Thread stopThread = new Thread(() =>
                        {
                            Console.WriteLine("Press 's' and Enter to stop recording.");
                            while (Console.ReadLine() != "s") ;
                            cts.Cancel();
                        });

                        stopThread.Start();

                        string response = "666";
                        response = EncryptString(response);
                        byte[] responseData = Encoding.ASCII.GetBytes(response);
                        stream.Write(responseData, 0, responseData.Length);
                        Console.WriteLine("Sent: {0}", DecryptString(response));

                        BufferedWaveProvider waveProvider = new BufferedWaveProvider(new WaveFormat(44100, 16, 2));
                        WaveOutEvent waveOut = new WaveOutEvent();

                        waveOut.Init(waveProvider);
                        waveOut.Play();

                        byte[] buffer = new byte[4096];
                        int bytesRead;

                        try
                        {
                            while (!token.IsCancellationRequested)
                            {
                                if (stream.DataAvailable)
                                {
                                    if ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                                    {
                                        waveProvider.AddSamples(buffer, 0, bytesRead);
                                    }
                                }
                                else
                                {
                                    Thread.Sleep(10); // Prevent tight loop if no data is available
                                }
                            }
                        }
                        finally
                        {
                            response = "6661";
                            response = EncryptString(response);
                            responseData = Encoding.ASCII.GetBytes(response);
                            stream.Write(responseData, 0, responseData.Length);
                            Console.WriteLine("Sent: {0}", DecryptString(response));

                            waveOut.Stop();
                            Console.WriteLine("Serves Listening Stopped.");
                        }
                    }
                    else
                    {
                        getMessage = false;
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("No Such an option");
                        Console.ForegroundColor = ConsoleColor.White;
                        Thread.Sleep(1000);
                    }

                    if (getMessage)
                    {
                        // Get Message
                        byte[] buffer = new byte[dataReadSize];
                        int bytes = stream.Read(buffer, 0, buffer.Length);
                        string data = Encoding.ASCII.GetString(buffer, 0, bytes);
                        data = DecryptString(data);
                        Console.WriteLine("Received From Client: {0}", data);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception: {0}", ex.Message);
                }
            }
            // exit from client processing
            processingClient = null;
        }

        static void PrintMenu()
        {
            Console.WriteLine($"\nConnected to client No: {processinClientIndex}");
            Console.WriteLine("\nMenu:");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[Command No] [Protocol value] - [Description]");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("\n0 - Stop Processing This Client");
            Console.WriteLine("1 (1) - Ping (Check If Listening)");
            Console.WriteLine("2 (80) - Request IP");
            Console.WriteLine("3 (15) - Request Device Name");
            Console.WriteLine("4 (96) - Request Registry Of Blocking Processes");
            Console.WriteLine("5 (22) - Request List Of Running Processes");
            Console.WriteLine("6 (78) - Get Limit Start and End Time");
            Console.WriteLine("7 (12) - Is Holiday");
            Console.WriteLine("8 (13) - Set Holiday");
            Console.WriteLine("50 (69) - Set Registry To Block Processes");
            Console.WriteLine("51 (72) - Set Data Read Size");
            Console.WriteLine("52 (97) - Set Limit Start Time");
            Console.WriteLine("53 (98) - Set Limit End Time");
            Console.WriteLine("100 (666) - Listen To Computer's Sound");
        }

        // Threads
        static void ClientsCleaner()
        {
            while (true)
            {
                lock (clients)
                {
                    // Check The Connections
                    for (int i = 0; i < clients.Count; i++)
                    {
                        TcpClient current = clients[i];
                        if (current.Client.Poll(0, SelectMode.SelectRead) && current.Client.Available == 0)
                        {
                            Console.WriteLine($"Client {i} disconnected");
                            clients.Remove(current);
                        }
                    }
                }

                Thread.Sleep(1500);
            }
        }
        static void ClientsAccepter(TcpListener server)
        {
            while (true)
            {
                // Accept new connections
                TcpClient client = server.AcceptTcpClient();
                Console.WriteLine("Client connected!");

                lock (clients) clients.Add(client);

                Thread.Sleep(3000);
            }
        }

        // Special Functions
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
        static void ClearNetworkStream(NetworkStream stream)
        {
            // Check if data is available and read it
            while (stream.DataAvailable)
            {
                byte[] buffer = new byte[1024]; // Adjust buffer size if necessary
                stream.Read(buffer, 0, buffer.Length);
            }
        }

        // Cryptography
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