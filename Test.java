import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

public class Test{

    public static void main(String[] args) {
        SecretKey Symmetrickey = createAESKey();

        System.out.println("**********************"); 
        System.out.println("Testing Symmetric key"); 
        System.out.println("The Symmetric Key is :" + DatatypeConverter.printHexBinary(Symmetrickey.getEncoded())); 
        System.out.println("**********************"); 
    }

}