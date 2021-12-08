import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Camelia с = new Camelia();
        Scanner in = new Scanner(System.in);
        String PlainText, EncText, Password;
        byte[] IV, Key;
        System.out.println("Enter key length in bits");
        String lengthKeyBit = in.nextLine();
        int length = Integer.parseInt(lengthKeyBit);
        с.keyLen(length);
        System.out.println("Enter  E/D");
        String modeCipher = in.nextLine();
        switch (modeCipher) {
            case ("E"):
                System.out.println("Enter the name of the file to encrypt");
                String Plaintext = in.nextLine();
                System.out.println("Enter the name of the file where to write the encrypted text");
                EncText = in.nextLine();
                System.out.println("Enter password");
                Password = in.nextLine();
                Key = с.PassToKey(Password);
                IV = с.InitializationVector();
                с.writeInitializationVector(IV, EncText);
                с.EncryptAndWriteRead(Plaintext, EncText, Key, IV);
                break;
            case ("D"):
                System.out.println("Enter the name of the file to decrypt");
                EncText = in.nextLine();
                System.out.println("Enter the file name where to write the decrypted text");
                PlainText = in.nextLine();
                System.out.println("Enter password ");
                Password = in.nextLine();
                Key = с.PassToKey(Password);
                IV = с.readInitializationVector(EncText);
                с.DecryptAndWRiteRead(PlainText, EncText, Key, IV);
                break;

        }
    }
}
