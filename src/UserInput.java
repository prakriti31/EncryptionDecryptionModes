import java.util.Scanner;

public class UserInput {

    public static final String DEFAULT_AES_KEY = "DEFAULTAESKEY123";  // 16 characters for AES
    public static final String DEFAULT_DES_KEY = "DEFAULTK";          // 8 characters for DES
    public static final String DEFAULT_3DES_KEY = "DEFAULTDESKEY12345678901";

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);
        int choice = 0;
        boolean exit = false;

        while (!exit) {
            // Display the main menu
            System.out.println("===========================================");
            System.out.println("                    Menu                   ");
            System.out.println("===========================================");
            System.out.println(" 1. Substitution Cipher");
            System.out.println("     A. Shift Cipher");
            // HELLO 3 -> KHOOR
            System.out.println("     B. Permutation Cipher");
            // HELLO 3,1,4,2,5 -> ELHLO
            System.out.println(" 2. Transposition Cipher");
            System.out.println("     A. Simple Transposition");
            // HELLO WORLD 2,1,4,3 -> e lHorlo lwd
            System.out.println("     B. Double Transposition");
            // HELLO WORLD 3,1,4,2 2,1,3,4 -> hloelw orld o
            System.out.println(" 3. Vigenere Cipher");
            // HELLO KEY
            System.out.println(" 4. Encryption Algorithms");
            System.out.println("     A. AES-128");
            System.out.println("     B. DES");
            System.out.println("     C. 3DES");
            System.out.println(" 5. Encryption Modes");
            System.out.println("     A. ECB");
            System.out.println("     B. CBC");
            System.out.println("     C. CFB");
            System.out.println("     D. OFB");
            System.out.println(" 6. Exit");
            System.out.println("===========================================");
            // Prompt for user choice
            System.out.print("Enter your choice (1-6): ");
            try {
                choice = scanner.nextInt();
                scanner.nextLine();  // Consume the newline character

                // Check if the choice is within the valid range
                if (choice < 1 || choice > 6) {
                    System.out.println("Invalid choice. Please select a number between 1 and 6.");
                    continue; // Re-prompt for input
                }
                switch (choice) {
                    case 1:
                        Functionalities.handleSubstitutionCipher(scanner);
                        break;
                    case 2:
                        Functionalities.handleTranspositionCipher(scanner);
                        break;
                    case 3:
                        Functionalities.handleVigenereCipher(scanner);
                        break;
                    case 4:
                        Functionalities.handleEncryptionAlgorithms(scanner);
                        break;
                    case 5:
                        Functionalities.handleEncryptionModes(scanner);
                        break;
                    case 6:
                        System.out.println("Exiting...");
                        exit = true;
                        break;
                    default:
                        System.out.println("Invalid choice. Please choose between 1 and 6.");
                        break;
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            System.out.println();
        }

        scanner.close();
    }


}
