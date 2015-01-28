package secusock.cipher;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;

public class SharingKey
{
	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		
		return generator.genKeyPair();
	}
	
	public static String encodePublicKey(KeyPair keyPair) throws Exception
	{
		byte[] publicKey = keyPair.getPublic().getEncoded();
		
		Encoder encoder = Base64.getEncoder();
		return encoder.encodeToString(publicKey);
	}
	
	public static PublicKey decodePublicKey(String givenKey) throws Exception
	{
		if(givenKey == null || givenKey.length() == 0) return null;
		
		Decoder decoder = Base64.getDecoder();
		byte[] publicKey = decoder.decode(givenKey);
		
		X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
		return keyFactory.generatePublic(spec);
	}
	
	public static String encrypt(PublicKey publicKey, byte[] message) throws Exception
	{
		byte[] cipherText = null;
		
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		cipherText = cipher.doFinal(message);
		
		Encoder encoder = Base64.getEncoder();		
		return encoder.encodeToString(cipherText);
	}
	
	public static byte[] decrypt(PrivateKey privateKey, String cipherMessage) throws Exception
	{
		byte[] decrypted = null;
		
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		
		Decoder decoder = Base64.getDecoder();
		decrypted = cipher.doFinal(decoder.decode(cipherMessage));
		
		return decrypted;
	}
}