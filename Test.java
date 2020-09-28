import java.security.KeyPair;

import javax.crypto.SecretKey;

public class Test {

    public static void main(String[] args) throws Exception {
        /**
         * SymmetricEncryption
         */
        System.out.println("**********************");
        System.out.println("Testing Symmetric Encryption...");

        SecretKey Symmetrickey = SymmetricEncryption.createAESKey();
        byte[] initial = SymmetricEncryption.createInitializationVector();
        String text = "Testing symmetric encyption!!!";
        byte[] cipherText = SymmetricEncryption.performAESEncyption(text, Symmetrickey, initial);
        String decrypedText = SymmetricEncryption.performAESDecryption(cipherText, Symmetrickey, initial);

        System.out.println("The Symmetric Key is :" + new String(Symmetrickey.getEncoded()));
        // need to fix this
        System.out.println("The Ciphertext is :" + new String(Symmetrickey.getEncoded()));
        System.out.println("The plain text is " + text);
        System.out.println("The decrypted text is :" + decrypedText);
        System.out.println("**********************");

        /**
         * AsymmetricEncryption
         */
        System.out.println("**********************");
        System.out.println("Testing Asymmetric Encryption...");

        //need to get input file
        KeyPair kp = AsymmetricEncryption.generateRSAKeyPair();
        //need to hash
        //need to create signature
        //need to verify
        byte[] cipherText2 = AsymmetricEncryption.performRSAEncryption(text, kp.getPrivate());
        String decrypedText2 = AsymmetricEncryption.performRSADecryption(cipherText2, kp.getPublic());

        System.out.println("The public Key is :" + new String(kp.getPublic().getEncoded()));
        System.out.println("The private Key is :" + new String(kp.getPrivate().getEncoded()));
        //need to fix this
        System.out.println("The Ciphertext is :" + new String(Symmetrickey.getEncoded()));
        System.out.println("The plain text is " + text);
        System.out.println("The decrypted text is :" + decrypedText2);
        System.out.println("**********************");


    }

}