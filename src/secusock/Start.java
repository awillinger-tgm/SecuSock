package secusock;

import java.security.KeyPair;

import javax.crypto.SecretKey;

import secusock.cipher.SessionKey;
import secusock.cipher.SharingKey;

public class Start
{
	public static void main(String[] args) throws Exception
	{
		// side which receives the shared key
		KeyPair keyPair = SharingKey.generateKeyPair();
		String myKey = SharingKey.encodePublicKey(keyPair);
		
		System.out.println("Key: %s".format(myKey));
		
		// side which generates the shared key
		SecretKey commKey = SessionKey.generateKey();
		
		String cipherText = SharingKey.encrypt(SharingKey.decodePublicKey(myKey), commKey.getEncoded());
		System.out.println("Encrypted: "+cipherText);
		
		// side which receives the shared key
		byte[] decryptedText = SharingKey.decrypt(keyPair.getPrivate(), cipherText);
		SecretKey deciphKey = SessionKey.getKey(decryptedText);
		
		String encrypted = SessionKey.encrypt(deciphKey, "Hello World");

		System.out.println("Ciphered message: "+encrypted);
		
		String decrypted = SessionKey.decrypt(commKey, encrypted);
		System.out.println("Deciphered message: "+decrypted);
	}
}
