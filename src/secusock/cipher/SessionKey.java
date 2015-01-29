package secusock.cipher;

import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class supplies methods for for generating and using AES SecretKeys.
 * It is being used to encrypt plain text messages.
 * 
 * @author Andreas Willinger
 * @version 20150128.1
 */
public class SessionKey
{
	/**
	 * Generates a new AES key with a key size of 256 bits.
	 * 
	 * @return A SecretKey instance containing the generated AES key
	 * @throws Exception
	 */
	public static SecretKey generateKey() throws Exception
	{
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		
		return keyGenerator.generateKey();
	}
	
	/**
	 * Returns a new SecretKey instance from the given key byte sequence.
	 * 
	 * @param givenKey The key, in a byte sequence form
	 * @return A SecretKey instance containing the supplied key
	 * @throws Exception
	 */
	public static SecretKey getKey(byte[] givenKey) throws Exception
	{		
		SecretKey spec = new SecretKeySpec(givenKey, 0, givenKey.length, "AES");
		
		return spec;
	}
	
	/**
	 * Encrypts the given message using the given SecretKey and returns the result as a
	 * Base64 encoded String.
	 * 
	 * @param secretKey A SecretKey instance containing the AES key to be used for the operation
	 * @param message The message to encrypt, as a String.
	 * @return The encrypted message, as a Base64 String.
	 * @throws Exception
	 */
	public static String encrypt(SecretKey secretKey, String message) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES");
		
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] cipherText = cipher.doFinal(message.getBytes("utf-8"));
		
		Encoder encoder = Base64.getEncoder();
		
		return encoder.encodeToString(cipherText);
	}
	
	/**
	 * Decrypts the given cipherText using the given SecretKey and returns the decrypted
	 * String.
	 * 
	 * @param secretKey A SecretKey instance to be used for decryption.
	 * @param cipherText The encrypted message, as a Base64 String
	 * @return The decrypted text
	 * 
	 * @throws Exception
	 */
	public static String decrypt(SecretKey secretKey, String cipherText) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES");
		Decoder decoder = Base64.getDecoder();
		
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] decryptText = cipher.doFinal(decoder.decode(cipherText));
		
		return new String(decryptText);
	}
}