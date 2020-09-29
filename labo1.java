import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.Base64;
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
	 * Problems: 1.Can get random error during decryption process 2.lane 87
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {

		// Initial values
		String decryptedMessage = "";
		String originalMessage = "";

		// Symmetric key used for message encryption/decryption with initialization
		// vector
		SecretKey Symmetrickey = SymmetricEncryption.createAESKey();
		byte[] initial = SymmetricEncryption.createInitializationVector();
		System.out.println("The Symmetric Key is :" + Base64.getEncoder().encodeToString(Symmetrickey.getEncoded()));

		// Keypair used for Encryption and Decryption
		KeyPair EncryptionKeys = AsymmetricEncryption.generateRSAKeyPair();
		// Keypair used for Signing and Verifying
		KeyPair SigningKeys = AsymmetricEncryption.generateRSAKeyPair();

		// Random salt used for hashing
		byte[] salt = Hash.generateRandomSalt();

		// Reading content of File
		File file = new File("plain-text.txt");
		// File file = new File("src/plain-text.txt");

		Scanner scanner = new Scanner(file);
		System.out.println("Read textfile...");
		System.out.println("The messages are: ");
		// read line by line
		while (scanner.hasNextLine()) {
			// process each line
			String testText = scanner.nextLine();
			originalMessage = originalMessage + "\n" + testText;
			System.out.println(testText);
		}
		scanner.close();

		// Sender
		// Encrypting the message
		byte[] cipherText = SymmetricEncryption.performAESEncyption(originalMessage, Symmetrickey, initial);

		// Sign the message using the sender's private key
		byte[] hashedOriginalMessage = Hash.createSHA2Hash(originalMessage, salt);
		byte[] messageSignature = DigitalSignature.createDigitalSignature(hashedOriginalMessage,
				SigningKeys.getPrivate());

		// Encrypting the symmetric Key using the sender's public key
		byte[] encryptedSymmetrickey = AsymmetricEncryption.performRSAEncryption(new String(Symmetrickey.getEncoded()),
				EncryptionKeys.getPublic());

		System.out.println(
				"The Encrypted Symmetric Key is :" + Base64.getEncoder().encodeToString(encryptedSymmetrickey));
		// Receiver
		// Decrypting Symmetric key using receiver's private key
		String decryptedSymmetrickey = AsymmetricEncryption.performRSADecryption(encryptedSymmetrickey,
				EncryptionKeys.getPrivate());

		// Decrypting the message with the decrypted symmetric key
		byte[] symKey = decryptedSymmetrickey.getBytes();
		SecretKey originalKey = new SecretKeySpec(symKey, 0, symKey.length, "AES");
		System.out.println(
				"The Decrypted Symmetric Key is :" + Base64.getEncoder().encodeToString(originalKey.getEncoded()));
		// Need to fix this
		decryptedMessage = SymmetricEncryption.performAESDecryption(cipherText, originalKey, initial);
		System.out.println("The decrypted message is : " + decryptedMessage);

		// Verify Hash
		byte[] tmpHash = Hash.createSHA2Hash(decryptedMessage, salt);
		String passwordHash = Hash.hashPassword(decryptedMessage);
		System.out.println(passwordHash);
		boolean isVerifiedHash = Hash.verifyPassord(passwordHash, passwordHash);
		/**
		 * if (isVerifiedHash) { System.out.println("Hash has been verified and
		 * confirmed"); } else { System.out.println("There is a mistake with the hash");
		 * }
		 */

		// Verify signature
		boolean isVerifiedSignature = DigitalSignature.verifyDigitalSignature(tmpHash, messageSignature,
				SigningKeys.getPublic());
		if (isVerifiedSignature) {
			System.out.println("Signature has been verified and confirmed");
		} else {
			System.out.println("There is a mistake with the signature");
		}

	}

}
