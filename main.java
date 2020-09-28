import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class main{
	KeyPair EncryptionKeys = generateRSAKeyPair();
	KeyPair SigningKeys = generateRSAKeyPair();

	String testText = "This is a test!";

	//Hashing and Signing
	byte[] hashedInput = createSHA2Hash(testText, generateRandomSalt());

	System.out.println(hashedInput);

}