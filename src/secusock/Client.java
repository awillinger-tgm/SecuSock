package secusock;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;

import javax.crypto.SecretKey;

import secusock.cipher.SessionKey;
import secusock.cipher.SharingKey;

/**
 * This class implements the SecuSock client, which takes user input and sends
 * it to the server.
 * 
 * @author Andreas Willinger
 * @version 20150129.1
 */
public class Client
{
	private String host = "";
	private int port = -1;
	// SharingKey
	private KeyPair keyPair;
	// SessionKey
	private SecretKey sessionKey;

	public Client(String host, int port)
	{
		// Sockets don't really like "localhost" addresses
		this.host = (host.equals("localhost")) ? "127.0.0.1" : host;
		this.port = port;
	}

	public static void main(String[] args)
	{
		try
		{
			// static context, ugh
			Client client = new Client(args[0], Integer.parseInt(args[1]));
			System.out
					.println("Welcome to SecuSock!\nThis application allows you to send plain-text and encrypted message to a server.");
			System.out
					.println("\nAvailable commands are:\n\t!keys - generate a new SessioNKey and enable encryption.\n\t_quit - exit the application\n");
			client.run();
		}
		catch (ArrayIndexOutOfBoundsException | NumberFormatException ex)
		{
			System.err.println("Missing parameters or invalid parameter types!");
			System.out.println("Usage:\njava Client <host> <port>\nExample: java Client 127.0.0.1 1234");
			System.out.println("\t<host> The IP of the host the server is running on.");
			System.out.println("\t<port> The port the server is running on.");
		}
	}

	/**
	 * Opens a socket connection to the server and reads user input. Then either
	 * requests a SessionKey from the server or sends the message (encrypted) to
	 * the server.
	 */
	public void run()
	{
		try (BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
				Socket socket = new Socket(this.host, this.port);
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));)
		{
			while (true)
			{
				System.out.print("Command> ");

				String fromUser = stdIn.readLine();
				String fromServer;

				if (fromUser != null)
				{
					// sanitize string to check for commands
					// remove whitespace + make all characters lower case
					String sanitized = fromUser.trim().toLowerCase();

					// generate a new SharingKey and request
					if (sanitized.equals("!keys"))
					{
						// locally save the RSA KeyPair, for decrypting the
						// sessionkey we get from the server
						this.keyPair = SharingKey.generateKeyPair();

						// send public key to server
						out.println("GENKEY|" + SharingKey.encodePublicKey(this.keyPair));
						out.flush();

						System.out.println("Sent request to server to generate a new SessionKey.");
					}
					else if (sanitized.equals("_quit"))
					{
						System.out.println("Closing sockets and shutting down.");

						break;
					}
					// no command entered
					// check if a SessionKey was set, and if yes, send a
					// encrypted message
					else if (this.sessionKey != null)
					{

						String encrypted = SessionKey.encrypt(this.sessionKey, fromUser);
						System.out.println("Sending encrypted message: " + encrypted);

						out.println("ENCMSG|" + encrypted);
						out.flush();
					}
					// send message as plain-text
					else
					{
						System.out.println("Sending plain-text message: " + fromUser);

						out.println("PLAINMSG|" + fromUser);
						out.flush();

					}

					// read reply from server
					while ((fromServer = in.readLine()) != null)
					{
						this.handleServerMessage(fromServer);
						break;
					}
				}
				else
				{
					System.err.println("Invalid command specified!");
					break;
				}
			}
		}
		catch (Exception ex)
		{
			System.err.println("Fatal error: " + ex.getMessage());
		}
	}

	/**
	 * Handles messages received from the server.
	 * 
	 * @param message
	 *            The message which was received from the server, as a String.
	 * @throws Exception An Exception thrown by one of the cipher classes.
	 */
	private void handleServerMessage(String message) throws Exception
	{
		if (message == null || message.length() == 0)
		{
			System.err.println("Invalid, empty message from server.");
			return;
		}

		// messages have the format COMMAND|PAYLOAD
		String command = message.substring(0, message.indexOf("|"));
		String payload = message.substring(message.indexOf("|") + 1, message.length());

		if (command.equals("SETKEY"))
		{
			// decrypt the received sessionkey using our private key
			byte[] decrypted = SharingKey.decrypt(this.keyPair.getPrivate(), payload);
			this.sessionKey = SessionKey.getKey(decrypted);

			System.out.println("Got a new SessionKey from server.");
			System.out.println("All messages are now being transmitted AES 256 bit encrypted!");
		}
		else if (command.equals("GOTMESSAGE"))
		{
			System.out.println("Server got message.");
		}
		else
		{
			System.err.println("Got an unknown command from server: " + command);
		}
	}
}