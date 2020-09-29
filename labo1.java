import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Scanner;
import java.io.File;
import java.io.FileNotFoundException;

public class labo1 {

	/**
	 * Problems:
	 * 1.Can get random error during decryption process
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		
		//Initial values
		String decryptedMessage = "";
		String originalMessage = "";
		
		//Symmetric key used for message encryption/decryption with initialization vector
		SecretKey Symmetrickey = SymmetricEncryption.createAESKey();
		byte[] initial = SymmetricEncryption.createInitializationVector();
		System.out.println("The Symmetric Key is :" + new String(Symmetrickey.getEncoded()));
		
		// Keypair used for Encryption and Decryption
		KeyPair EncryptionKeys = AsymmetricEncryption.generateRSAKeyPair();
		// Keypair used for Signing and Verifying
		KeyPair SigningKeys = AsymmetricEncryption.generateRSAKeyPair();
		
		//Random salt used for hashing
		byte[] salt = Hash.generateRandomSalt();
		

<<<<<<< HEAD
		File file = new File("plain-text.txt");
=======
		//Reading content of File
		File file = new File("src/plain-text.txt");
>>>>>>> f136f258922b301a69419d98e407a61703c0d05f
		Scanner scanner = new Scanner(file);
		System.out.println("Read textfile...");
		// read line by line
		while (scanner.hasNextLine()) {
			// process each line
			String testText = scanner.nextLine();
			originalMessage = originalMessage + "\n" + testText;
			System.out.println(testText);			
		}
		scanner.close();
		
		//Sender
		//Encrypting the message
		byte[] cipherText = SymmetricEncryption.performAESEncyption(originalMessage, Symmetrickey, initial);

		// Sign the message using the sender's private key
		byte[] hashedOriginalMessage = Hash.createSHA2Hash(originalMessage, salt);
		byte[] messageSignature = DigitalSignature.createDigitalSignature(hashedOriginalMessage,
				SigningKeys.getPrivate());

		// Encrypting the symmetric Key using the sender's public key
		byte[] encryptedSymmetrickey = AsymmetricEncryption
				.performRSAEncryption(new String(Symmetrickey.getEncoded()), EncryptionKeys.getPublic());
		
		
		// Receiver
		//Decrypting Symmetric key using receiver's private key
		String decryptedSymmetrickey = AsymmetricEncryption.performRSADecryption(encryptedSymmetrickey,EncryptionKeys.getPrivate());
		
		//Decrypting the message with the decrypted symmetric key
		byte[] symKey = decryptedSymmetrickey.getBytes();
		SecretKey originalKey = new SecretKeySpec(symKey, 0, symKey.length, "AES");
		System.out.println("The Decrypted Symmetric Key is :" + new String(originalKey.getEncoded()));
		decryptedMessage = SymmetricEncryption.performAESDecryption(cipherText, originalKey, initial);
		System.out.println("The decrypted message is : \n" + decryptedMessage);
		
		
		//Verify signature
		byte[] tmpHash = Hash.createSHA2Hash(decryptedMessage, salt);
		boolean isVerified = DigitalSignature.verifyDigitalSignature(tmpHash, messageSignature,SigningKeys.getPublic());
		if(isVerified == true) {
			System.out.println("Signature has been verified and confirmed");
		} else {
			System.out.println("There is a mistake with the signature");
		}

	}

}
