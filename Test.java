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
        System.out.println("The Ciphertext is :" + new String(Symmetrickey.getEncoded()));
        System.out.println("The plain text is " + text);
        System.out.println("The decrypted text is :" + decrypedText);
        System.out.println("**********************");

        /**
         * AsymmetricEncryption
         */
        System.out.println("**********************");
        System.out.println("Testing Asymmetric Encryption...");

    }

}