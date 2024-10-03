import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class Functionalities {

         // 8 characters for 3DES (used the same as DES)

    // ************************** MENU HANDLING METHODS WITH SWITCH CASES **************************


    // Handling the first substitution Cipher choice
    static void handleSubstitutionCipher(Scanner scanner) {
        System.out.println("You chose Substitution Cipher.");
        System.out.println("A. Shift Cipher");
        System.out.println("B. Permutation Cipher");
        System.out.print("Choose A or B: ");
        String subChoice = scanner.nextLine().toUpperCase();
        String decryptionChoice;
        switch (subChoice) {
            case "A":
                System.out.println("You chose Shift Cipher.");
                System.out.print("Enter the plaintext to encrypt using Substitution Cipher: ");
                String plaintextShift = scanner.nextLine();
                System.out.print("Enter the shift value (integer): ");
                int shiftValue = scanner.nextInt();
                scanner.nextLine(); // Consume newline character
                String encryptedShift = shiftEncryptMethod(plaintextShift, shiftValue);
                System.out.println("Encrypted Text: " + encryptedShift);
                System.out.print("Do you want to decrypt this message?(Y/N) ");
                decryptionChoice = scanner.nextLine();
                scanner.nextLine(); // Consume newline character
                switch (decryptionChoice) {
                    case "Y":
                        System.out.println("Plain text after decryption is: " + decryptShiftCipher(encryptedShift, shiftValue));
                        break;
                    case "N":
                        break;
                }
                break;

            case "B":
                System.out.println("You chose Permutation Cipher.");
                System.out.print("Enter the plaintext to encrypt using Permutation Cipher: ");
                String plaintextPermutation = scanner.nextLine();
                System.out.print("Enter the permutation key (as comma-separated integers): ");
                String keyInput = scanner.nextLine();
                int[] permutationKey = parseKeyInput(keyInput);
                String encryptedPermutation = permutationEncryptMethod(plaintextPermutation, permutationKey);
                System.out.println("Encrypted text: " + encryptedPermutation);
                System.out.print("Do you want to decrypt this message?(Y/N) ");
                decryptionChoice = scanner.nextLine();
                scanner.nextLine(); // Consume newline character
                switch (decryptionChoice) {
                    case "Y":
                        System.out.println("Plain text after decryption is: " + decryptPermutationCipher(encryptedPermutation, permutationKey));
                        break;
                    case "N":
                        break;
                }
                break;

            default:
                System.out.println("Invalid choice. Please choose A or B.");
                break;
        }
    }

    // Handling the second Transposition Cipher choice
    static void handleTranspositionCipher(Scanner scanner) {
        System.out.println("You chose Transposition Cipher.");
        System.out.println("A. Simple Transposition");
        System.out.println("B. Double Transposition");
        System.out.print("Choose A or B: ");
        String subChoice = scanner.nextLine().toUpperCase();
        String decryptionChoice;
        switch (subChoice) {
            case "A":
                System.out.println("You chose Simple Transposition.");
                System.out.print("Enter the plaintext to encrypt using Simple Transposition Cipher: ");
                String plaintextSimple = scanner.nextLine();
                System.out.print("Enter the transposition key (as comma-separated integers): ");
                String keyInputSimple = scanner.nextLine();
                int[] transpositionKey = parseKeyInput(keyInputSimple);
                String encryptedSimple = simpleTranspositionEncryptMethod(plaintextSimple, transpositionKey);
                System.out.println("Encrypted text: " + encryptedSimple);
                System.out.print("Do you want to decrypt this message?(Y/N) ");
                decryptionChoice = scanner.nextLine();
                scanner.nextLine(); // Consume newline character
                switch (decryptionChoice) {
                    case "Y":
                        System.out.println("Plain text after decryption is: " + decryptSimpleTranspositionCipher(encryptedSimple, transpositionKey));
                        break;
                    case "N":
                        break;
                }
                break;

            case "B":
                System.out.println("You chose Double Transposition.");
                System.out.print("Enter the plaintext to encrypt using Double Transposition Cipher: ");
                String plaintextDouble = scanner.nextLine();
                System.out.print("Enter the first key (as comma-separated integers): ");
                int[] key1 = parseKeyInput(scanner.nextLine());
                System.out.print("Enter the second key (as comma-separated integers): ");
                int[] key2 = parseKeyInput(scanner.nextLine());
                String encryptedDouble = doubleTranspositionEncryptMethod(plaintextDouble, key1, key2);
                System.out.println("Encrypted text: " + encryptedDouble);
                System.out.print("Do you want to decrypt this message?(Y/N) ");
                decryptionChoice = scanner.nextLine();
                scanner.nextLine(); // Consume newline character
                switch (decryptionChoice) {
                    case "Y":
                        System.out.println("Plain text after decryption is: " + decryptDoubleTranspositionCipher(encryptedDouble, key1, key2));
                        break;
                    case "N":
                        break;
                }
                break;

            default:
                System.out.println("Invalid choice. Please choose A or B.");
                break;
        }
    }

    // Handling the third substitution Vigenere choice
    static void handleVigenereCipher(Scanner scanner) {
        System.out.println("You chose Vigenere Cipher.");
        System.out.print("Enter the plaintext to encrypt using Vigenere Cipher: ");
        String plaintext = scanner.nextLine().toUpperCase();
        System.out.print("Enter the keyword: ");
        String keyword = scanner.nextLine().toUpperCase();
        String encryptedVigenere = vigenereEncryptMethod(plaintext, keyword);
        System.out.println("Encrypted Text: " + encryptedVigenere);
        System.out.print("Do you want to decrypt this message?(Y/N) ");
        String decryptionChoice = scanner.nextLine();
        scanner.nextLine(); // Consume newline character
        switch (decryptionChoice) {
            case "Y":
                System.out.println("Plain text after decryption is: " + decryptVigenere(encryptedVigenere, keyword));
                break;
            case "N":
                break;
        }
    }

    // Handling the fourth Encryption Algorithm choices
    static void handleEncryptionAlgorithms(Scanner scanner) {
        System.out.println("You chose Encryption Algorithms.");
        System.out.println("     A. AES-128");
        System.out.println("     B. DES");
        System.out.println("     C. 3DES");
        System.out.print("Choose A, B, or C: ");
        String subChoice = scanner.nextLine().toUpperCase();
        String decryptionChoice;

        try {
            System.out.print("Enter the text you want to encrypt using the chosen algorithm: ");
            String plaintext = scanner.nextLine(); // Read user input

            // Set default key and key length based on the chosen algorithm
            String algorithm;
            int keyLength;
            String defaultKey;

            switch (subChoice) {
                case "A":
                    algorithm = "AES";
                    keyLength = 16; // 16 characters for AES
                    defaultKey = UserInput.DEFAULT_AES_KEY; // Default AES key
                    break;
                case "B":
                    algorithm = "DES";
                    keyLength = 8; // 8 characters for DES
                    defaultKey = UserInput.DEFAULT_DES_KEY; // Default DES key
                    break;
                case "C":
                    algorithm = "DESede"; // 3DES
                    keyLength = 8; // 8 characters for 3DES
                    defaultKey = UserInput.DEFAULT_3DES_KEY; // Default 3DES key
                    break;
                default:
                    System.out.println("Invalid choice. Please choose A, B, or C.");
                    return;
            }

            // Option to enter encryption key or use a default key
            System.out.print("Do you want to enter a custom key? (Y/N): ");
            String keyChoice = scanner.nextLine().toUpperCase();
            SecretKey key;

            if (keyChoice.equals("Y")) {
                System.out.printf("Enter your %d-character key for %s: ", keyLength, algorithm);
                String keyInput = scanner.nextLine();
                if (keyInput.length() != keyLength) {
                    System.out.printf("Key must be exactly %d characters long.\n", keyLength);
                    return;
                }
                key = new SecretKeySpec(keyInput.getBytes(), algorithm);
            } else {
                key = new SecretKeySpec(defaultKey.getBytes(), algorithm); // Use default key
            }

            // Encryption and decryption logic based on the chosen algorithm
            String encryptedText;
            switch (subChoice) {
                case "A": // AES-128
                    encryptedText = encryptAESMethod(plaintext, key);
                    System.out.println("Encrypted Text (AES-128): " + encryptedText);
                    break;
                case "B": // DES
                    encryptedText = encryptDESMethod(plaintext, key);
                    System.out.println("Encrypted Text (DES): " + encryptedText);
                    break;
                case "C": // 3DES
                    encryptedText = encrypt3DESMethod(plaintext, key);
                    System.out.println("Encrypted Text (3DES): " + encryptedText);
                    break;
                default:
                    System.out.println("Invalid choice. Please choose A, B, or C.");
                    return;
            }

            // Decryption option
            System.out.print("Do you want to decrypt this message? (Y/N): ");
            decryptionChoice = scanner.nextLine().toUpperCase();
            if (decryptionChoice.equals("Y")) {
                String decryptedText = "";
                switch (subChoice) {
                    case "A":
                        decryptedText = decryptAES(encryptedText, key);
                        break;
                    case "B":
                        decryptedText = decryptDES(encryptedText, key);
                        break;
                    case "C":
                        decryptedText = decrypt3DES(encryptedText, key);
                        break;
                }
                System.out.println("Plain text after decryption is: " + decryptedText);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    // Handling the fifth Encryption Mode choices
    static void handleEncryptionModes(Scanner scanner) {
        System.out.println("You chose Encryption Modes.");
        System.out.println("     A. ECB");
        System.out.println("     B. CBC");
        System.out.println("     C. CFB");
        System.out.println("     D. OFB");
        System.out.print("Choose A, B, C or D: ");
        String subChoice = scanner.nextLine().toUpperCase();

        try {
            // Prompt user for plaintext
            System.out.print("Enter the plaintext to encrypt: ");
            String plaintext = scanner.nextLine(); // Read user input

            // Option to enter encryption key or use a default key
            System.out.print("Do you want to enter a custom key? (Y/N): ");
            String keyChoice = scanner.nextLine().toUpperCase();
            SecretKey key;

            if (keyChoice.equals("Y")) {
                System.out.print("Enter your 16-character key for AES: ");
                String keyInput = scanner.nextLine();
                if (keyInput.length() != 16) {
                    System.out.println("Key must be exactly 16 characters long.");
                    return;
                }
                key = new SecretKeySpec(keyInput.getBytes(), "AES");
            } else {
                key = new SecretKeySpec(UserInput.DEFAULT_AES_KEY.getBytes(), "AES"); // Use default key
            }

            // Generate a random initialization vector (IV)
            byte[] iv = new byte[16]; // 16 bytes for AES
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv); // Fill the IV with random bytes

            String encryptedText;
            String decryptionChoice;
            switch (subChoice) {
                case "A":
                    encryptedText = encryptAESUsingECBMethod(plaintext, key);
                    System.out.println("Encrypted Text: " + encryptedText);
                    System.out.print("Do you want to decrypt this message?(Y/N) ");
                    decryptionChoice = scanner.nextLine();
                    scanner.nextLine(); // Consume newline character
                    switch (decryptionChoice) {
                        case "Y":
                            System.out.println("Plain text after decryption is: " + decryptAESUsingECBMode(encryptedText, key));
                            break;
                        case "N":
                            break;
                    }
                    break;

                case "B":
                    encryptedText = encryptAESUsingCBCMethod(plaintext, key, iv);
                    System.out.println("Encrypted Text: " + encryptedText);
                    System.out.print("Do you want to decrypt this message?(Y/N) ");
                    decryptionChoice = scanner.nextLine();
                    scanner.nextLine(); // Consume newline character
                    switch (decryptionChoice) {
                        case "Y":
                            System.out.println("Plain text after decryption is: " + decryptAESUsingCBC(encryptedText, key, iv));
                            break;
                        case "N":
                            break;
                    }
                    break;

                case "C":
                    encryptedText = encryptAESUsingCFBMethod(plaintext, key, iv);
                    System.out.println("Encrypted Text: " + encryptedText);
                    System.out.print("Do you want to decrypt this message?(Y/N) ");
                    decryptionChoice = scanner.nextLine();
                    scanner.nextLine(); // Consume newline character
                    switch (decryptionChoice) {
                        case "Y":
                            System.out.println("Plain text after decryption is: " + decryptAESUsingCFB(encryptedText, key, iv));
                            break;
                        case "N":
                            break;
                    }
                    break;

                case "D":
                    encryptedText = encryptAESUsingOFBMethod(plaintext, key, iv);
                    System.out.println("Encrypted Text: " + encryptedText);
                    System.out.print("Do you want to decrypt this message?(Y/N) ");
                    decryptionChoice = scanner.nextLine();
                    scanner.nextLine(); // Consume newline character
                    switch (decryptionChoice) {
                        case "Y":
                            System.out.println("Plain text after decryption is: " + decryptAESUsingOFB(encryptedText, key, iv));
                            break;
                        case "N":
                            break;
                    }
                    break;

                default:
                    System.out.println("Invalid choice. Please choose A, B, C or D.");
                    return;
            }

            System.out.println("Encrypted Text: " + encryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ************************** HELPER METHODS **************************

    // Helper method for parsing the key input
    private static int[] parseKeyInput(String keyInput) {
        String[] keyStrings = keyInput.split(",");
        int[] key = new int[keyStrings.length];
        for (int i = 0; i < keyStrings.length; i++) {
            key[i] = Integer.parseInt(keyStrings[i].trim());
        }
        return key;
    }


    // ************************** ENCRYPTION METHODS **************************


    // Method to encrypt plaintext using Shift Cipher
    public static String shiftEncryptMethod(String text, int shift){
            // Making the String mutable
            StringBuilder ciphertext = new StringBuilder();

            // Running a for loop to iterate through characters and change their values
            // according to the requirement
            for (int i = 0; i < text.length(); i++) {
                // assigning each character consecutively to char value c
                char c = text.charAt(i);

                // Check if the character is a letter
                if (Character.isLetter(c)) {
                    char base = Character.isUpperCase(c) ? 'A' : 'a';
                    // Shift the letter and wrap around using modulo operation
                    char shiftedChar = (char) ((c - base + shift) % 26 + base);
                    ciphertext.append(shiftedChar);
                } else {
                    // If not a letter, just add the character as it is
                    ciphertext.append(c);
                }
            }

            return ciphertext.toString();
        }

    // Method to encrypt plaintext using Permutation Cipher
        public static String permutationEncryptMethod(String plaintext, int[] key){
            // "HELLOWORLD" [3, 1, 4, 2]
            // Calculate the block size from the key length
            // Pad the plaintext with spaces if it isn't a multiple of the block size
            // "HELL" (first 4 characters)
            // "OWOR" (next 4 characters)
            // "LD " (padded with spaces because of missing 2 chars)
            // The letter will be given the position as mentioned in the key.
            // For eg "HELLO" -> [2, 3, 1, 4, 5] Ans: ELHLO
            // Process each block of the plaintext

            StringBuilder ciphertext = new StringBuilder();
            int blockSize = key.length;

            // Pad the plaintext with spaces if it isn't a multiple of the block size
            StringBuilder plaintextBuilder = new StringBuilder(plaintext);
            while (plaintextBuilder.length() % blockSize != 0) {
                plaintextBuilder.append(" ");
            }
            plaintext = plaintextBuilder.toString();

            // Process each block of the plaintext
            for (int i = 0; i < plaintext.length(); i += blockSize) {
                char[] block = new char[blockSize];

                // Rearrange the characters in the block according to the permutation key
                for (int j = 0; j < blockSize; j++) {
                    block[j] = plaintext.charAt(i + key[j] - 1);  // Apply the permutation process
                }

                // Append the rearranged block to the ciphertext
                ciphertext.append(block);
            }

            return ciphertext.toString();
        }

    // Method to encrypt plaintext using Simple Transposition Cipher
        public static String simpleTranspositionEncryptMethod(String plaintext, int[] key){
            StringBuilder ciphertext = new StringBuilder();

            // Calculate the number of rows based on key length
            int numRows = (int) Math.ceil((double) plaintext.length() / key.length);

            // Create a 2D array (grid) to store the plaintext in columns
            char[][] grid = new char[numRows][key.length];

            // Fill the grid with the plaintext characters
            int index = 0;
            for (int row = 0; row < numRows; row++) {
                for (int col = 0; col < key.length; col++) {
                    if (index < plaintext.length()) {
                        grid[row][col] = plaintext.charAt(index);
                        index++;
                    } else {
                        // Pad with space if plaintext is shorter than the grid size
                        grid[row][col] = ' ';
                    }
                }
            }

            // Rearrange the grid according to the key and build the ciphertext
            for (int i : key) {
                int keyCol = i - 1; // Key is 1-based, so we subtract 1 for 0-based indexing
                for (int row = 0; row < numRows; row++) {
                    ciphertext.append(grid[row][keyCol]);
                }
            }

            return ciphertext.toString();
        }

    // Method to encrypt plaintext using Double Transposition Cipher
        public static String doubleTranspositionEncryptMethod(String plaintext, int[] key1, int[] key2){
            // Perform first transposition
            String firstPass = simpleTranspositionEncryptMethod(plaintext, key1);

            // Perform second transposition on the result
            return simpleTranspositionEncryptMethod(firstPass, key2);
        }

    // Method to encrypt plaintext using Vigenère Cipher
        public static String vigenereEncryptMethod (String plaintext, String keyword){
            StringBuilder ciphertext = new StringBuilder();
            // Make sure that the key is in uppercase, throughout
            keyword = keyword.toUpperCase();

//        Plaintext:   A  T  T  A  C  K  A  T  D  A  W  N
//        Keyword:     L  E  M  O  N  L  E  M  O  N  L  E
//        Step 2: Shift each letter:
//        A + L = (0 + 11) = L
//        T + E = (19 + 4) = X
//        T + M = (19 + 12) = F
//        A + O = (0 + 14) = O
//        C + N = (2 + 13) = P
//        K + L = (10 + 11) = V
//        A + E = (0 + 4) = E
//        T + M = (19 + 12) = F
//        D + O = (3 + 14) = R
//        A + N = (0 + 13) = N
//        W + L = (22 + 11) = H
//        N + E = (13 + 4) = R

            for (int i = 0; i < plaintext.length(); i++) {
                char plainChar = plaintext.charAt(i);

                // Formula
                // Pi = (Ci - Ki) + 26
                // Pi - decrypted plaintext letter.
                // Ci - ciphertext letter (converted to an index 0–25).
                // Ki - keyword letter (converted to an index 0–25).
                // Adding 26 ensures we avoid negative numbers during the subtraction.

                if (Character.isLetter(plainChar)) {
                    int shift = (plainChar - 'A' + keyword.charAt(i % keyword.length()) - 'A') % 26;
                    ciphertext.append((char) (shift + 'A'));
                } else {
                    ciphertext.append(plainChar); // Non-letter characters remain unchanged
                }
            }

            return ciphertext.toString();
        }

    // Method to encrypt plaintext using AES Algorithm
    // We implement it using ECB by default
    public static String encryptAESMethod(String plaintext, SecretKey key) throws Exception {
        // specifies the encryption algorithm (AES), the mode of operation (ECB), and the padding scheme (PKCS5).
        // AES: Advanced Encryption Standard, a symmetric key algorithm.
        // ECB (Electronic Codebook): A mode of operation that divides plaintext into blocks and encrypts each block independently.
        // PKCS5Padding: A padding scheme that ensures that the plaintext is a multiple of the block size (16 bytes for AES).
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  // AES in ECB mode with padding
        // Initialises cipher instance in encryption mode using the provided secret key.
        // Key is used to set up the cipher's internal state for encryption.
        // This key must be the same during decryption to retrieve the original plaintext.
        cipher.init(Cipher.ENCRYPT_MODE, key);  // Initialize cipher for encryption
        // plaintext.getBytes() converts the input string into a byte array using the default character encoding.
        // cipher.doFinal() method processes the input bytes, encrypting them based on the initialized cipher.
        // This method returns an array of bytes representing the encrypted data.
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());  // Encrypt the plaintext
        // Converts the encrypted byte array into a Base64 encoded string.
        return Base64.getEncoder().encodeToString(encryptedBytes);  // Convert encrypted bytes to Base64 string
    }

    // Method to encrypt plaintext using DES Algorithm
    public static String encryptDESMethod(String plaintext, SecretKey key) throws Exception {
        // Create a Cipher object for DES
        // Code is similar to AES
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key); // Initialize the cipher for encryption
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes()); // Encrypt the plaintext
        return Base64.getEncoder().encodeToString(encryptedBytes); // Convert to Base64 string
    }

    // Method to encrypt plaintext using 3DES Algorithm
    public static String encrypt3DESMethod(String plaintext, SecretKey key) throws Exception {
        // Create a Cipher object for 3DES
        // Code is similar to AES
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key); // Initialize the cipher for encryption

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes()); // Encrypt the plaintext
        return Base64.getEncoder().encodeToString(encryptedBytes); // Convert to Base64 string
    }

    // Method to encrypt plaintext using AES in ECB mode
    public static String encryptAESUsingECBMethod(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // AES in ECB mode with padding
        cipher.init(Cipher.ENCRYPT_MODE, key); // Initialize the cipher for encryption

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes()); // Encrypt the plaintext
        return Base64.getEncoder().encodeToString(encryptedBytes); // Convert to Base64 string
    }

    // Method to encrypt plaintext using AES in CBC mode
    public static String encryptAESUsingCBCMethod(String plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // AES in CBC mode with padding
        IvParameterSpec ivParams = new IvParameterSpec(iv); // Create IV parameter spec
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParams); // Initialize the cipher for encryption

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes()); // Encrypt the plaintext
        return Base64.getEncoder().encodeToString(encryptedBytes); // Convert to Base64 string
    }

    // Method to encrypt plaintext using AES in CFB mode
    public static String encryptAESUsingCFBMethod(String plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding"); // AES in CFB mode with padding
        IvParameterSpec ivParams = new IvParameterSpec(iv); // Create IV parameter spec
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParams); // Initialize the cipher for encryption

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes()); // Encrypt the plaintext
        return Base64.getEncoder().encodeToString(encryptedBytes); // Convert to Base64 string
    }

    // Method to encrypt plaintext using AES in OFB mode
    public static String encryptAESUsingOFBMethod(String plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding"); // AES in OFB mode with padding
        IvParameterSpec ivParams = new IvParameterSpec(iv); // Create IV parameter spec
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParams); // Initialize the cipher for encryption

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes()); // Encrypt the plaintext
        return Base64.getEncoder().encodeToString(encryptedBytes); // Convert to Base64 string
    }

    // ************************** DECRYPTION METHODS **************************

    // Method to decrypt ciphertext using Shift Cipher
    public static String decryptShiftCipher(String encryptedText, int shift) {
        StringBuilder decryptedText = new StringBuilder();

        // Iterate through each character in the encrypted text
        for (char ch : encryptedText.toCharArray()) {
            // Check if the character is an uppercase letter
            if (Character.isUpperCase(ch)) {
                char decryptedChar = (char) (((ch - 'A' - shift + 26) % 26) + 'A'); // Adjust with modulo
                decryptedText.append(decryptedChar);
            }
            // Check if the character is a lowercase letter
            else if (Character.isLowerCase(ch)) {
                char decryptedChar = (char) (((ch - 'a' - shift + 26) % 26) + 'a'); // Adjust with modulo
                decryptedText.append(decryptedChar);
            } else {
                // If it's not a letter, just append it unchanged
                decryptedText.append(ch);
            }
        }

        return decryptedText.toString(); // Return the decrypted text
    }

    // Method to decrypt ciphertext using Permutation Cipher
    public static String decryptPermutationCipher(String ciphertext, int[] key) {
        // Create a char array for the decrypted text
        StringBuilder plaintext = new StringBuilder();
        int blockSize = key.length;

        // Process each block of the ciphertext
        for (int i = 0; i < ciphertext.length(); i += blockSize) {
            char[] block = new char[blockSize];

            // Rearrange the characters in the block back to their original positions using the inverse of the permutation key
            for (int j = 0; j < blockSize; j++) {
                block[key[j] - 1] = ciphertext.charAt(i + j);  // Reverse the permutation process
            }

            // Append the rearranged block to the plaintext
            plaintext.append(block);
        }

        return plaintext.toString();
    }

    // Method to decrypt ciphertext using Single Transposition
    public static String decryptSimpleTranspositionCipher(String encryptedText, int[] key) {
        int numCols = key.length;
        int numRows = (int) Math.ceil((double) encryptedText.length() / numCols);
        char[][] grid = new char[numRows][numCols];

        // Fill the grid column by column according to the key
        int index = 0;
        for (int j : key) {
            int colIndex = j - 1; // Convert to 0-based index
            for (int row = 0; row < numRows; row++) {
                if (index < encryptedText.length()) {
                    grid[row][colIndex] = encryptedText.charAt(index);
                    index++;
                } else {
                    // Pad with spaces if necessary
                    grid[row][colIndex] = ' ';
                }
            }
        }

        // Build the decrypted text by reading the grid row-wise
        StringBuilder decryptedText = new StringBuilder();
        for (int row = 0; row < numRows; row++) {
            for (int col = 0; col < numCols; col++) {
                decryptedText.append(grid[row][col]);
            }
        }

        return decryptedText.toString().trim(); // Trim any trailing spaces
    }

    // Method to decrypt ciphertext using Double Transposition
    public static String decryptDoubleTranspositionCipher(String encryptedText, int[] key1, int[] key2) {
        // First, decrypt using the second key (reverse order)
        String intermediateText = decryptSimpleTranspositionCipher(encryptedText, key2);
        // Then, decrypt the intermediate text using the first key (reverse order)
        return decryptSimpleTranspositionCipher(intermediateText, key1);
    }

    // Method to decrypt ciphertext using AES
    public static String decryptAES(String encryptedText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  // AES in ECB mode with padding
        cipher.init(Cipher.DECRYPT_MODE, key);  // Initialize cipher for decryption
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));  // Decrypt the ciphertext
        return new String(decryptedBytes);  // Convert decrypted bytes to string
    }

    // Method to decrypt ciphertext using DES
    public static String decryptDES(String ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key); // Initialize the cipher for decryption

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext)); // Decrypt the Base64 string
        return new String(decryptedBytes); // Convert decrypted bytes back to string
    }

    // Method to decrypt ciphertext using 3DES
    public static String decrypt3DES(String ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key); // Initialize the cipher for decryption

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext)); // Decrypt the Base64 string
        return new String(decryptedBytes); // Convert decrypted bytes back to string
    }

    // Decrypt the ciphertext using the Vigenère Cipher
    public static String decryptVigenere(String ciphertext, String keyword) {
        StringBuilder plaintext = new StringBuilder();
        keyword = keyword.toUpperCase();

        for (int i = 0; i < ciphertext.length(); i++) {
            char cipherChar = ciphertext.charAt(i);

            if (Character.isLetter(cipherChar)) {
                int shift = (cipherChar - keyword.charAt(i % keyword.length()) + 26) % 26;
                plaintext.append((char) (shift + 'A'));
            } else {
                plaintext.append(cipherChar); // Non-letter characters remain unchanged
            }
        }

        return plaintext.toString();
    }

    // Method to decrypt ciphertext using AES in ECB mode
    public static String decryptAESUsingECBMode(String ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Create a Cipher object for AES
        cipher.init(Cipher.DECRYPT_MODE, key); // Initialize the cipher for decryption

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext)); // Decrypt the Base64 string
        return new String(decryptedBytes); // Convert decrypted bytes back to string
    }

    // Method to decrypt ciphertext using AES in CBC mode
    public static String decryptAESUsingCBC(String ciphertext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Create a Cipher object for AES
        IvParameterSpec ivParams = new IvParameterSpec(iv); // Create IV parameter spec
        cipher.init(Cipher.DECRYPT_MODE, key, ivParams); // Initialize the cipher for decryption

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext)); // Decrypt the Base64 string
        return new String(decryptedBytes); // Convert decrypted bytes back to string
    }

    // Method to decrypt ciphertext using AES in CFB mode
    public static String decryptAESUsingCFB(String ciphertext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding"); // Create a Cipher object for AES
        IvParameterSpec ivParams = new IvParameterSpec(iv); // Create IV parameter spec
        cipher.init(Cipher.DECRYPT_MODE, key, ivParams); // Initialize the cipher for decryption

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext)); // Decrypt the Base64 string
        return new String(decryptedBytes); // Convert decrypted bytes back to string
    }

    // Method to decrypt ciphertext using AES in OFB mode
    public static String decryptAESUsingOFB(String ciphertext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding"); // Create a Cipher object for AES
        IvParameterSpec ivParams = new IvParameterSpec(iv); // Create IV parameter spec
        cipher.init(Cipher.DECRYPT_MODE, key, ivParams); // Initialize the cipher for decryption

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext)); // Decrypt the Base64 string
        return new String(decryptedBytes); // Convert decrypted bytes back to string
    }

}
