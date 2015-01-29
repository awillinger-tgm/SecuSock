package secusock;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

import javax.crypto.SecretKey;

import secusock.cipher.SessionKey;
import secusock.cipher.SharingKey;

/**
 * This class implements the SecuSock server, which handles SessioNKey
 * generation and replies to the client.
 * 
 * @author Andreas Willinger
 * @version 20150129.1
 */
public class Server
{
	private int port = -1;

	// SessioNkey
	private SecretKey sessionKey;

	public Server(int port)
	{
		this.port = port;
	}

	public static void main(String[] args) throws Exception
	{
		try
		{
			// static context, ugh
			Server server = new Server(Integer.parseInt(args[0]));
			System.out.println("Starting SecuSock server ..");

			server.run();
		}
		catch (ArrayIndexOutOfBoundsException | NumberFormatException ex)
		{
			System.err.println("Missing parameters or invalid parameter types!");
			System.out.println("Usage:\njava Server <port>\nExample: java Server 1234");
			System.out.println("\t<port> The port the server is running on.");
		}
	}

	/**
	 * Opens a server socket and waits for connections and handles messages once
	 * they arrive.
	 */
	public void run()
	{
		System.out.println("SecuSock server started, waiting for connections ..");

		while (true)
		{
			try (ServerSocket serverSocket = new ServerSocket(this.port);
					Socket clientSocket = serverSocket.accept();
					PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
					BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));)
			{
				System.out.println("Connection accepted from " + clientSocket.getInetAddress() + ":"
						+ clientSocket.getPort());

				String inputLine = "";

				while ((inputLine = in.readLine()) != null)
				{
					// messages have the format COMMAND|PAYLOAD
					String command = inputLine.substring(0, inputLine.indexOf("|"));
					String payload = inputLine.substring(inputLine.indexOf("|") + 1, inputLine.length());

					// Client sent a public key and requests a common SessionKey
					// Generate one, and send the SessionKey back encrypted.
					if (command.equals("GENKEY"))
					{
						this.sessionKey = SessionKey.generateKey();

						System.out.println("\nReceived SessionKey generation request");
						System.out.println("--------------------------------------");
						System.out.println("Public key: " + payload);

						String cipherText = SharingKey.encrypt(SharingKey.decodePublicKey(payload),
								this.sessionKey.getEncoded());

						out.println("SETKEY|" + cipherText);
					}
					// Client sent a encrypted message
					else if (command.equals("ENCMSG"))
					{
						String deciphered = SessionKey.decrypt(this.sessionKey, payload);

						System.out.println("\nReceived encrypted message");
						System.out.println("--------------------------");
						System.out.println("Encrypted: " + payload + "\nDecrypted: " + deciphered);

						out.println("GOTMESSAGE|0");
					}
					// Client sent plain-text message
					else if (command.equals("PLAINMSG"))
					{
						System.out.println("\nReceived plain-text message");
						System.out.println("---------------------------");
						System.out.println("Message: " + payload);
						out.println("GOTMESSAGE|0");
					}
					// Client sent something unknown
					else
					{
						out.println("INVALID|Unknown command");
					}
				}
			}
			catch (Exception ex)
			{
				System.err.println("Fatal error: " + ex.getMessage());
				break;
			}
			System.out.println("Connection closed.");
		}
	}
}