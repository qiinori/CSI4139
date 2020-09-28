import javax.crypto.SecretKey;

public class Test{

    public static void main(String[] args) throws Exception {
        SecretKey Symmetrickey = SymmetricEncryption.createAESKey();

        System.out.println("**********************"); 
        System.out.println("Testing Symmetric key"); 
        System.out.println("The Symmetric Key is :" + new String(Symmetrickey.getEncoded())); 
        System.out.println("**********************"); 
    }

}