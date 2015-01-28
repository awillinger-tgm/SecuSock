package secusock.cipher;

import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SessionKey
{
	public static SecretKey generateKey() throws Exception
	{
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		
		return keyGenerator.generateKey();
	}
	
	public static SecretKey getKey(byte[] givenKey) throws Exception
	{		
		SecretKey spec = new SecretKeySpec(givenKey, 0, givenKey.length, "AES");
		
		return spec;
	}
	
	public static String encrypt(SecretKey secretKey, String message) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES");
		
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] cipherText = cipher.doFinal(message.getBytes("utf-8"));
		
		Encoder encoder = Base64.getEncoder();
		
		return encoder.encodeToString(cipherText);
	}
	
	public static String decrypt(SecretKey secretKey, String cipherText) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES");
		Decoder decoder = Base64.getDecoder();
		
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] decryptText = cipher.doFinal(decoder.decode(cipherText));
		
		return new String(decryptText);
	}
}