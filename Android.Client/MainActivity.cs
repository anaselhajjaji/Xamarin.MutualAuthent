using System;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

using Android.App;
using Android.Widget;
using Android.OS;
using Java.Security;
using Javax.Net.Ssl;

namespace Android.Client
{
    [Activity(Label = "Android.Client", MainLauncher = true, Icon = "@mipmap/icon")]
    public class MainActivity : Activity, IHandshakeCompletedListener
    {
        public void HandshakeCompleted(HandshakeCompletedEvent e)
        {
            var socket = e.Socket;
            var session = e.Session;
        }
        
        protected override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);

            // Set our view from the "main" layout resource
            SetContentView(Resource.Layout.Main);

            // Get our button from the layout resource,
            // and attach an event to it
            Button javaButton = FindViewById<Button>(Resource.Id.javaTLS);

            javaButton.Click += async delegate
            {
                string message = await JavaConnectAndReceiveMessage();
                Toast.MakeText(this, message, ToastLength.Long).Show();
            };
            
            Button netButton = FindViewById<Button>(Resource.Id.netTLS);

            netButton.Click += async delegate
            {
                //  hostName
                var hostName = "192.168.1.103";
                
                //  port
                var port = 56111;
                
                //  certificate and password
                var password = "password";
                using (Stream keyin = Resources.OpenRawResource(Resource.Raw.ClientPFX))
                using (MemoryStream memStream = new MemoryStream())
                {
                    keyin.CopyTo(memStream);
                    var certificates = new X509Certificate2Collection(new X509Certificate2(memStream.ToArray(), password));
                    string message = await NetConnectAndReceiveMessage(hostName, port, certificates);
                    Toast.MakeText(this, message, ToastLength.Long).Show();
                }
            };
        }

        async Task<String> NetConnectAndReceiveMessage(string hostName, int port, X509Certificate2Collection certificates)
        {
            return await Task.Run(() =>
            {
                // Create a TCP/IP client socket.
                // machineName is the host running the server application.
                TcpClient client = new TcpClient(hostName, port);
                Console.WriteLine("Client connected.");
                // Create an SSL stream that will close the client's stream.
                SslStream sslStream = new SslStream(
                    client.GetStream(),
                    false,
                    ValidateServerCertificate);

                // The server name must match the name on the server certificate.
                try
                {
                    sslStream.AuthenticateAsClient(hostName, certificates, SslProtocols.Tls12, true);
                    DisplaySecurityLevel(sslStream);
                    DisplaySecurityServices(sslStream);
                    DisplayCertificateInformation(sslStream);
                    DisplayStreamProperties(sslStream);
                }
                catch (AuthenticationException e)
                {
                    Console.WriteLine("Exception: {0}", e.Message);
                    if (e.InnerException != null)
                    {
                        Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                    }
                    Console.WriteLine("Authentication failed - closing the connection.");
                    client.Close();
                    return "";
                }
                // Encode a test message into a byte array.
                // Signal the end of the message using the "<EOF>".
                byte[] messsage = Encoding.UTF8.GetBytes("Hello from the client.<EOF>");
                // Send hello message to the server. 
                sslStream.Write(messsage);
                sslStream.Flush();
                // Read message from the server.
                string serverMessage = ReadMessage(sslStream);
                // Close the client connection.
                client.Close();

                return serverMessage;
            });
        }

        static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return (sslPolicyErrors == SslPolicyErrors.None);
        }

        static void DisplaySecurityLevel(SslStream stream)
        {
            // FIXME Not Working
            //Console.WriteLine("Cipher: {0} strength {1}", stream.CipherAlgorithm, stream.CipherStrength);
            //Console.WriteLine("Hash: {0} strength {1}", stream.HashAlgorithm, stream.HashStrength);
            //Console.WriteLine("Key exchange: {0} strength {1}", stream.KeyExchangeAlgorithm, stream.KeyExchangeStrength);
            Console.WriteLine("Protocol: {0}", stream.SslProtocol);
        }

        static void DisplaySecurityServices(SslStream stream)
        {
            Console.WriteLine("Is authenticated: {0} as server? {1}", stream.IsAuthenticated, stream.IsServer);
            Console.WriteLine("IsSigned: {0}", stream.IsSigned);
            Console.WriteLine("Is Encrypted: {0}", stream.IsEncrypted);
        }

        static void DisplayStreamProperties(SslStream stream)
        {
            Console.WriteLine("Can read: {0}, write {1}", stream.CanRead, stream.CanWrite);
            Console.WriteLine("Can timeout: {0}", stream.CanTimeout);
        }

        static void DisplayCertificateInformation(SslStream stream)
        {
            // FIXME NOT WORKING
            // Console.WriteLine("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

            X509Certificate localCertificate = stream.LocalCertificate;
            if (stream.LocalCertificate != null)
            {
                Console.WriteLine("Local cert was issued to {0} and is valid from {1} until {2}.",
                    localCertificate.Subject,
                    localCertificate.GetEffectiveDateString(),
                    localCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Local certificate is null.");
            }
            // Display the properties of the client's certificate.
            X509Certificate remoteCertificate = stream.RemoteCertificate;
            if (remoteCertificate != null)
            {
                Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
                    remoteCertificate.Subject,
                    remoteCertificate.GetEffectiveDateString(),
                    remoteCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Remote certificate is null.");
            }
        }

        async Task<String> JavaConnectAndReceiveMessage()
        {
            var hostName = "192.168.1.103";
            var port = 56111;

            // Build Java Keystore
            Stream keyin = Resources.OpenRawResource(Resource.Raw.ClientBKS);
            KeyStore ks = KeyStore.GetInstance("BKS");
            ks.Load(keyin, "password".ToCharArray());

            return await Task.Run(() => {

                String defaultAlgorithm = KeyManagerFactory.DefaultAlgorithm;
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.GetInstance(defaultAlgorithm);
                keyManagerFactory.Init(ks, "password".ToCharArray());

                SSLContext sslContext = SSLContext.GetInstance("TLS");
                sslContext.Init(keyManagerFactory.GetKeyManagers(), null, null);

                SSLSocketFactory sslSocketFactory = sslContext.SocketFactory;
                Javax.Net.Ssl.SSLSocket sslSocket = (Javax.Net.Ssl.SSLSocket)sslSocketFactory.CreateSocket(new Java.Net.Socket(hostName, port), hostName, port, false);
                sslSocket.AddHandshakeCompletedListener(this);
                sslSocket.NeedClientAuth = true;
                sslSocket.KeepAlive = true;
                sslSocket.StartHandshake();

                // Exchange Messages
                Stream sslIS = sslSocket.InputStream;
                Stream sslOS = sslSocket.OutputStream;

                // Encode a test message into a byte array.
                // Signal the end of the message using the "<EOF>".
                byte[] messsage = Encoding.UTF8.GetBytes("Hello from the client.<EOF>");
                sslOS.Write(messsage, 0, messsage.Length);
                sslOS.Flush();

                string serverMessage = ReadMessage(sslIS);

                sslSocket.Close();
                
                return serverMessage;
            });
        }

        static string ReadMessage(Stream sslStream)
        {
            // Read the  message sent by the server.
            // The end of the message is signaled using the
            // "<EOF>" marker.
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                bytes = sslStream.Read(buffer, 0, buffer.Length);

                // Use Decoder class to convert from bytes to UTF8
                // in case a character spans two buffers.
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                // Check for EOF.
                if (messageData.ToString().IndexOf("<EOF>") != -1)
                {
                    break;
                }
            } while (bytes != 0);

            return messageData.ToString();
        }
    }
}

