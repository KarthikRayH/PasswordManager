import java.util.*;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javafx.application.Application;


public class PasswordManager {
    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
    private static final String ALGORITHM = "AES";
    private static final String DATA_FILE = "password_data.enc";
    private static final String KEY_FILE = "master.key";
    private static Scanner scanner = new Scanner(System.in);
    private static SecretKey secretKey;
    private static Map<String, PasswordEntry> passwordStorage = new HashMap<>();
    private static String masterPasswordHash = "";
    private static int loginAttempts = 0;
    private static final int MAX_LOGIN_ATTEMPTS = 3;
    
    // Password entry class to store additional metadata
    static class PasswordEntry {
        String encryptedPassword;
        String website;
        String username;
        String notes;
        LocalDateTime created;
        LocalDateTime lastModified;
        int accessCount;
        
        public PasswordEntry(String encryptedPassword, String website, String username, String notes) {
            this.encryptedPassword = encryptedPassword;
            this.website = website;
            this.username = username;
            this.notes = notes;
            this.created = LocalDateTime.now();
            this.lastModified = LocalDateTime.now();
            this.accessCount = 0;
        }
    }
    
    public static void main(String[] args) {
        System.out.println("==============================================");
        System.out.println("        ENHANCED PASSWORD MANAGER v2.0");
        System.out.println("==============================================");
        
        try {
            if (loadExistingData()) {
                if (authenticateUser()) {
                    System.out.println("\n✓ Welcome back to your secure password manager!");
                    mainMenu();
                } else {
                    System.out.println("\n✗ Authentication failed. Access denied.");
                    return;
                }
            } else {
                if (setupNewUser()) {
                    System.out.println("\n✓ Setup complete! Welcome to your password manager!");
                    mainMenu();
                } else {
                    System.out.println("✗ Setup failed. Exiting...");
                    return;
                }
            }
        } catch (Exception e) {
            System.out.println("Fatal error: " + e.getMessage());
        } finally {
            saveDataToFile();
        }
    }
    
    private static boolean loadExistingData() {
        File keyFile = new File(KEY_FILE);
        File dataFile = new File(DATA_FILE);
        
        if (keyFile.exists() && dataFile.exists()) {
            try {
                // Load master password hash
                String keyData = new String(Files.readAllBytes(keyFile.toPath()));
                masterPasswordHash = keyData.split("\\|")[0];
                
                // Load secret key
                byte[] keyBytes = Base64.getDecoder().decode(keyData.split("\\|")[1]);
                secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
                
                // Load password data
                loadPasswordData();
                return true;
            } catch (Exception e) {
                System.out.println("Error loading existing data: " + e.getMessage());
                return false;
            }
        }
        return false;
    }
    
    private static boolean authenticateUser() {
        System.out.println("\n=== USER AUTHENTICATION ===");
        
        while (loginAttempts < MAX_LOGIN_ATTEMPTS) {
            System.out.print("Enter your master password: ");
            String inputPassword = System.console() != null ? 
                new String(System.console().readPassword()) : scanner.nextLine();
            
            try {
                String inputHash = hashPassword(inputPassword);
                if (inputHash.equals(masterPasswordHash)) {
                    loginAttempts = 0;
                    return true;
                }
            } catch (Exception e) {
                System.out.println("Authentication error: " + e.getMessage());
            }
            
            loginAttempts++;
            System.out.println("Incorrect password. Attempts remaining: " + (MAX_LOGIN_ATTEMPTS - loginAttempts));
        }
        
        return false;
    }
    
    private static boolean setupNewUser() {
        System.out.println("\n=== FIRST TIME SETUP ===");
        System.out.println("Creating a new secure vault...");
        
        String masterPassword = "";
        String confirmPassword = "";
        
        // Get master password with confirmation
        while (true) {
            System.out.print("Create a master password (min 8 chars, mix of letters, numbers, symbols): ");
            masterPassword = System.console() != null ? 
                new String(System.console().readPassword()) : scanner.nextLine();
            
            if (!isPasswordStrong(masterPassword)) {
                System.out.println("Password too weak. Please use at least 8 characters with letters, numbers, and symbols.");
                continue;
            }
            
            System.out.print("Confirm master password: ");
            confirmPassword = System.console() != null ? 
                new String(System.console().readPassword()) : scanner.nextLine();
            
            if (masterPassword.equals(confirmPassword)) {
                break;
            } else {
                System.out.println("Passwords don't match. Please try again.");
            }
        }
        
        try {
            // Hash master password
            masterPasswordHash = hashPassword(masterPassword);
            
            // Generate encryption key
            secretKey = generateKey();
            
            // Save master data
            saveMasterData();
            
            System.out.println("✓ Setup complete! Your vault is now secured.");
            System.out.println("⚠️  WARNING: If you forget your master password, all data will be lost!");
            
            return true;
        } catch (Exception e) {
            System.out.println("Setup error: " + e.getMessage());
            return false;
        }
    }
    
    private static void mainMenu() {
        boolean running = true;
        
        while (running) {
            displayMainMenu();
            int choice = getChoice();
            
            switch (choice) {
                case 1:
                    generateNewPassword();
                    break;
                case 2:
                    addNewEntry();
                    break;
                case 3:
                    retrievePassword();
                    break;
                case 4:
                    viewAllEntries();
                    break;
                case 5:
                    searchEntries();
                    break;
                case 6:
                    editEntry();
                    break;
                case 7:
                    deleteEntry();
                    break;
                case 8:
                    securityAnalysis();
                    break;
                case 9:
                    exportData();
                    break;
                case 10:
                    importData();
                    break;
                case 11:
                    changeMasterPassword();
                    break;
                case 12:
                    showStatistics();
                    break;
                case 13:
                    running = exitProgram();
                    break;
                default:
                    System.out.println("Invalid choice. Please select 1-13.");
            }
            
            if (running) {
                System.out.println("\nPress Enter to continue...");
                scanner.nextLine();
                clearScreen();
            }
        }
    }
    
    private static void displayMainMenu() {
        System.out.println("\n╔══════════════════════════════════════╗");
        System.out.println("║            MAIN MENU                ║");
        System.out.println("╠══════════════════════════════════════╣");
        System.out.println("║  1. Generate secure password        ║");
        System.out.println("║  2. Add new password entry          ║");
        System.out.println("║  3. Retrieve password                ║");
        System.out.println("║  4. View all entries                 ║");
        System.out.println("║  5. Search entries                   ║");
        System.out.println("║  6. Edit entry                       ║");
        System.out.println("║  7. Delete entry                     ║");
        System.out.println("║  8. Security analysis                ║");
        System.out.println("║  9. Export data                      ║");
        System.out.println("║ 10. Import data                      ║");
        System.out.println("║ 11. Change master password          ║");
        System.out.println("║ 12. Show statistics                  ║");
        System.out.println("║ 13. Exit                             ║");
        System.out.println("╚══════════════════════════════════════╝");
        System.out.print("Choose an option (1-13): ");
    }
    
    private static int getChoice() {
        try {
            int choice = Integer.parseInt(scanner.nextLine().trim());
            return choice;
        } catch (NumberFormatException e) {
            return -1;
        }
    }
    
    private static void generateNewPassword() {
        System.out.println("\n=== PASSWORD GENERATOR ===");
        System.out.print("Password length (8-128): ");
        
        try {
            int length = Integer.parseInt(scanner.nextLine().trim());
            
            if (length < 8 || length > 128) {
                System.out.println("Length must be between 8 and 128 characters.");
                return;
            }
            
            System.out.println("\nPassword options:");
            System.out.println("1. Include all characters (letters, numbers, symbols)");
            System.out.println("2. Letters and numbers only");
            System.out.println("3. Custom character set");
            System.out.print("Choose option (1-3): ");
            
            int option = getChoice();
            String charset = CHARACTERS;
            
            switch (option) {
                case 2:
                    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                    break;
                case 3:
                    System.out.print("Enter custom characters to use: ");
                    charset = scanner.nextLine().trim();
                    if (charset.isEmpty()) {
                        System.out.println("Invalid character set.");
                        return;
                    }
                    break;
            }
            
            String password = generatePassword(length, charset);
            System.out.println("\n" + "=".repeat(50));
            System.out.println("Generated Password: " + password);
            System.out.println("Strength Rating: " + evaluateStrength(password));
            System.out.println("Entropy: " + calculateEntropy(password) + " bits");
            System.out.println("=".repeat(50));
            
            System.out.print("\nSave this password? (y/n): ");
            if (scanner.nextLine().trim().toLowerCase().startsWith("y")) {
                saveGeneratedPassword(password);
            }
            
        } catch (NumberFormatException e) {
            System.out.println("Please enter a valid number.");
        }
    }
    
    private static String generatePassword(int length, String charset) {
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();
        
        // For default charset, ensure character diversity
        if (charset.equals(CHARACTERS)) {
            password.append(getRandomChar("ABCDEFGHIJKLMNOPQRSTUVWXYZ", random));
            password.append(getRandomChar("abcdefghijklmnopqrstuvwxyz", random));
            password.append(getRandomChar("0123456789", random));
            password.append(getRandomChar("!@#$%^&*()-_=+[]{}|;:,.<>?", random));
            
            for (int i = 4; i < length; i++) {
                password.append(charset.charAt(random.nextInt(charset.length())));
            }
        } else {
            for (int i = 0; i < length; i++) {
                password.append(charset.charAt(random.nextInt(charset.length())));
            }
        }
        
        return shuffleString(password.toString(), random);
    }
    
    private static void addNewEntry() {
        System.out.println("\n=== ADD NEW PASSWORD ENTRY ===");
        
        System.out.print("Account/Service name: ");
        String account = scanner.nextLine().trim();
        if (account.isEmpty()) {
            System.out.println("Account name cannot be empty.");
            return;
        }
        
        System.out.print("Website/URL (optional): ");
        String website = scanner.nextLine().trim();
        
        System.out.print("Username/Email: ");
        String username = scanner.nextLine().trim();
        
        System.out.print("Password: ");
        String password = scanner.nextLine().trim();
        if (password.isEmpty()) {
            System.out.println("Password cannot be empty.");
            return;
        }
        
        System.out.print("Notes (optional): ");
        String notes = scanner.nextLine().trim();
        
        try {
            String encryptedPassword = encrypt(password);
            PasswordEntry entry = new PasswordEntry(encryptedPassword, website, username, notes);
            passwordStorage.put(account.toLowerCase(), entry);
            
            System.out.println("\n✓ Entry saved successfully!");
            System.out.println("Password strength: " + evaluateStrength(password));
            
            String strength = evaluateStrength(password);
            if (strength.equals("Weak") || strength.equals("Medium")) {
                System.out.println("⚠️  Consider using a stronger password for better security.");
            }
            
        } catch (Exception e) {
            System.out.println("Error saving entry: " + e.getMessage());
        }
    }
    
    private static void retrievePassword() {
        System.out.println("\n=== RETRIEVE PASSWORD ===");
        
        if (passwordStorage.isEmpty()) {
            System.out.println("No passwords saved yet.");
            return;
        }
        
        System.out.print("Enter account name: ");
        String account = scanner.nextLine().trim().toLowerCase();
        
        if (passwordStorage.containsKey(account)) {
            PasswordEntry entry = passwordStorage.get(account);
            
            try {
                String decryptedPassword = decrypt(entry.encryptedPassword);
                entry.accessCount++;
                entry.lastModified = LocalDateTime.now();
                
                System.out.println("\n" + "=".repeat(50));
                System.out.println("Account: " + account);
                System.out.println("Username: " + entry.username);
                System.out.println("Password: " + decryptedPassword);
                System.out.println("Website: " + (entry.website.isEmpty() ? "Not specified" : entry.website));
                System.out.println("Notes: " + (entry.notes.isEmpty() ? "None" : entry.notes));
                System.out.println("Created: " + entry.created.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
                System.out.println("Last accessed: " + entry.lastModified.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
                System.out.println("Access count: " + entry.accessCount);
                System.out.println("=".repeat(50));
                
            } catch (Exception e) {
                System.out.println("Error retrieving password: " + e.getMessage());
            }
        } else {
            System.out.println("No entry found for '" + account + "'");
            suggestSimilarEntries(account);
        }
    }
    
    private static void viewAllEntries() {
        System.out.println("\n=== ALL SAVED ENTRIES ===");
        
        if (passwordStorage.isEmpty()) {
            System.out.println("No entries saved yet.");
            return;
        }
        
        System.out.printf("%-20s %-25s %-20s %-15s%n", "Account", "Website", "Username", "Last Modified");
        System.out.println("-".repeat(80));
        
        List<Map.Entry<String, PasswordEntry>> sortedEntries = new ArrayList<>(passwordStorage.entrySet());
        sortedEntries.sort((a, b) -> a.getKey().compareToIgnoreCase(b.getKey()));
        
        for (Map.Entry<String, PasswordEntry> entry : sortedEntries) {
            String account = entry.getKey();
            PasswordEntry pe = entry.getValue();
            String website = pe.website.length() > 24 ? pe.website.substring(0, 21) + "..." : pe.website;
            String username = pe.username.length() > 19 ? pe.username.substring(0, 16) + "..." : pe.username;
            String lastMod = pe.lastModified.format(DateTimeFormatter.ofPattern("MM-dd HH:mm"));
            
            System.out.printf("%-20s %-25s %-20s %-15s%n", 
                account.length() > 19 ? account.substring(0, 16) + "..." : account,
                website.isEmpty() ? "-" : website,
                username.isEmpty() ? "-" : username,
                lastMod);
        }
        
        System.out.println("-".repeat(80));
        System.out.println("Total entries: " + passwordStorage.size());
    }
    
    private static void searchEntries() {
        System.out.println("\n=== SEARCH ENTRIES ===");
        
        if (passwordStorage.isEmpty()) {
            System.out.println("No entries to search.");
            return;
        }
        
        System.out.print("Enter search term (account, website, or username): ");
        String searchTerm = scanner.nextLine().trim().toLowerCase();
        
        if (searchTerm.isEmpty()) {
            System.out.println("Search term cannot be empty.");
            return;
        }
        
        List<String> matches = new ArrayList<>();
        
        for (Map.Entry<String, PasswordEntry> entry : passwordStorage.entrySet()) {
            String account = entry.getKey();
            PasswordEntry pe = entry.getValue();
            
            if (account.contains(searchTerm) || 
                pe.website.toLowerCase().contains(searchTerm) ||
                pe.username.toLowerCase().contains(searchTerm) ||
                pe.notes.toLowerCase().contains(searchTerm)) {
                matches.add(account);
            }
        }
        
        if (matches.isEmpty()) {
            System.out.println("No matches found for '" + searchTerm + "'");
        } else {
            System.out.println("\nFound " + matches.size() + " match(es):");
            for (int i = 0; i < matches.size(); i++) {
                String account = matches.get(i);
                PasswordEntry pe = passwordStorage.get(account);
                System.out.println((i + 1) + ". " + account + 
                    (pe.website.isEmpty() ? "" : " (" + pe.website + ")"));
            }
        }
    }
    
    private static void securityAnalysis() {
        System.out.println("\n=== SECURITY ANALYSIS ===");
        
        if (passwordStorage.isEmpty()) {
            System.out.println("No passwords to analyze.");
            return;
        }
        
        int weak = 0, medium = 0, strong = 0, veryStrong = 0;
        List<String> duplicates = new ArrayList<>();
        Map<String, List<String>> passwordMap = new HashMap<>();
        
        try {
            for (Map.Entry<String, PasswordEntry> entry : passwordStorage.entrySet()) {
                String account = entry.getKey();
                String password = decrypt(entry.getValue().encryptedPassword);
                String strength = evaluateStrength(password);
                
                switch (strength) {
                    case "Weak": weak++; break;
                    case "Medium": medium++; break;
                    case "Strong": strong++; break;
                    case "Very Strong": veryStrong++; break;
                }
                
                // Check for duplicates
                passwordMap.computeIfAbsent(password, k -> new ArrayList<>()).add(account);
            }
            
            // Find duplicates
            for (Map.Entry<String, List<String>> entry : passwordMap.entrySet()) {
                if (entry.getValue().size() > 1) {
                    duplicates.addAll(entry.getValue());
                }
            }
            
            System.out.println("\n📊 PASSWORD STRENGTH DISTRIBUTION:");
            System.out.println("Very Strong: " + veryStrong + " (" + (veryStrong * 100 / passwordStorage.size()) + "%)");
            System.out.println("Strong: " + strong + " (" + (strong * 100 / passwordStorage.size()) + "%)");
            System.out.println("Medium: " + medium + " (" + (medium * 100 / passwordStorage.size()) + "%)");
            System.out.println("Weak: " + weak + " (" + (weak * 100 / passwordStorage.size()) + "%)");
            
            if (!duplicates.isEmpty()) {
                System.out.println("\n⚠️  SECURITY ISSUES:");
                System.out.println("Duplicate passwords found in: " + String.join(", ", duplicates));
                System.out.println("Consider using unique passwords for each account.");
            }
            
            if (weak > 0 || medium > 0) {
                System.out.println("\n💡 RECOMMENDATIONS:");
                System.out.println("- Update weak/medium passwords to stronger ones");
                System.out.println("- Use the password generator for better security");
                System.out.println("- Enable 2FA where possible");
            } else {
                System.out.println("\n✅ Excellent! All passwords are strong.");
            }
            
        } catch (Exception e) {
            System.out.println("Error during analysis: " + e.getMessage());
        }
    }
    
    private static void showStatistics() {
        System.out.println("\n=== VAULT STATISTICS ===");
        
        if (passwordStorage.isEmpty()) {
            System.out.println("No data to show statistics for.");
            return;
        }
        
        int totalEntries = passwordStorage.size();
        int totalAccesses = passwordStorage.values().stream().mapToInt(e -> e.accessCount).sum();
        
        PasswordEntry oldest = passwordStorage.values().stream()
            .min((a, b) -> a.created.compareTo(b.created)).orElse(null);
        PasswordEntry newest = passwordStorage.values().stream()
            .max((a, b) -> a.created.compareTo(b.created)).orElse(null);
        PasswordEntry mostAccessed = passwordStorage.values().stream()
            .max((a, b) -> Integer.compare(a.accessCount, b.accessCount)).orElse(null);
        
        System.out.println("Total entries: " + totalEntries);
        System.out.println("Total password retrievals: " + totalAccesses);
        System.out.println("Average accesses per entry: " + (totalAccesses / totalEntries));
        
        if (oldest != null) {
            System.out.println("Oldest entry created: " + oldest.created.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
        }
        if (newest != null) {
            System.out.println("Newest entry created: " + newest.created.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
        }
        if (mostAccessed != null) {
            String accountName = passwordStorage.entrySet().stream()
                .filter(e -> e.getValue() == mostAccessed)
                .map(Map.Entry::getKey)
                .findFirst().orElse("Unknown");
            System.out.println("Most accessed: " + accountName + " (" + mostAccessed.accessCount + " times)");
        }
    }
    
    private static void editEntry() {
        System.out.println("\n=== EDIT ENTRY ===");
        
        if (passwordStorage.isEmpty()) {
            System.out.println("No entries to edit.");
            return;
        }
        
        viewAllEntries();
        System.out.print("\nEnter account name to edit: ");
        String account = scanner.nextLine().trim().toLowerCase();
        
        if (!passwordStorage.containsKey(account)) {
            System.out.println("Entry not found.");
            return;
        }
        
        PasswordEntry entry = passwordStorage.get(account);
        
        System.out.println("\nWhat would you like to edit?");
        System.out.println("1. Password");
        System.out.println("2. Username");
        System.out.println("3. Website");
        System.out.println("4. Notes");
        System.out.println("5. All fields");
        System.out.print("Choose option (1-5): ");
        
        int choice = getChoice();
        
        try {
            switch (choice) {
                case 1:
                    System.out.print("Enter new password: ");
                    String newPassword = scanner.nextLine().trim();
                    if (!newPassword.isEmpty()) {
                        entry.encryptedPassword = encrypt(newPassword);
                        System.out.println("Password updated. Strength: " + evaluateStrength(newPassword));
                    }
                    break;
                case 2:
                    System.out.print("Enter new username: ");
                    entry.username = scanner.nextLine().trim();
                    break;
                case 3:
                    System.out.print("Enter new website: ");
                    entry.website = scanner.nextLine().trim();
                    break;
                case 4:
                    System.out.print("Enter new notes: ");
                    entry.notes = scanner.nextLine().trim();
                    break;
                case 5:
                    System.out.print("New password: ");
                    String pwd = scanner.nextLine().trim();
                    if (!pwd.isEmpty()) {
                        entry.encryptedPassword = encrypt(pwd);
                    }
                    System.out.print("New username: ");
                    entry.username = scanner.nextLine().trim();
                    System.out.print("New website: ");
                    entry.website = scanner.nextLine().trim();
                    System.out.print("New notes: ");
                    entry.notes = scanner.nextLine().trim();
                    break;
                default:
                    System.out.println("Invalid choice.");
                    return;
            }
            
            entry.lastModified = LocalDateTime.now();
            System.out.println("✓ Entry updated successfully!");
            
        } catch (Exception e) {
            System.out.println("Error updating entry: " + e.getMessage());
        }
    }
    
    private static void deleteEntry() {
        System.out.println("\n=== DELETE ENTRY ===");
        
        if (passwordStorage.isEmpty()) {
            System.out.println("No entries to delete.");
            return;
        }
        
        viewAllEntries();
        System.out.print("\nEnter account name to delete: ");
        String account = scanner.nextLine().trim().toLowerCase();
        
        if (passwordStorage.containsKey(account)) {
            System.out.print("⚠️  Are you sure you want to delete entry for '" + account + "'? (yes/no): ");
            String confirm = scanner.nextLine().trim().toLowerCase();
            
            if (confirm.equals("yes")) {
                passwordStorage.remove(account);
                System.out.println("✓ Entry deleted successfully.");
            } else {
                System.out.println("Deletion cancelled.");
            }
        } else {
            System.out.println("Entry not found.");
        }
    }
    
    private static void exportData() {
        System.out.println("\n=== EXPORT DATA ===");
        
        if (passwordStorage.isEmpty()) {
            System.out.println("No data to export.");
            return;
        }
        
        System.out.println("⚠️  WARNING: Exported data will be in plain text!");
        System.out.print("Continue? (yes/no): ");
        
        if (!scanner.nextLine().trim().toLowerCase().equals("yes")) {
            return;
        }
        
        String filename = "passwords_export_" + 
            LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) + ".txt";
        
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("Password Manager Export - " + LocalDateTime.now());
            writer.println("=" + "=".repeat(50));
            
            for (Map.Entry<String, PasswordEntry> entry : passwordStorage.entrySet()) {
                String account = entry.getKey();
                PasswordEntry pe = entry.getValue();
                String password = decrypt(pe.encryptedPassword);
                
                writer.println("\nAccount: " + account);
                writer.println("Username: " + pe.username);
                writer.println("Password: " + password);
                writer.println("Website: " + pe.website);
                writer.println("Notes: " + pe.notes);
                writer.println("Created: " + pe.created);
                writer.println("-".repeat(30));
            }
            
            System.out.println("✓ Data exported to: " + filename);
            System.out.println("⚠️  Please secure this file and delete it when no longer needed!");
            
        } catch (Exception e) {
            System.out.println("Export failed: " + e.getMessage());
        }
    }
    
    private static void importData() {
        System.out.println("\n=== IMPORT DATA ===");
        System.out.println("This feature supports importing from CSV format:");
        System.out.println("Format: Account,Username,Password,Website,Notes");
        
        System.out.print("Enter CSV filename: ");
        String filename = scanner.nextLine().trim();
        
        try (Scanner fileScanner = new Scanner(new File(filename))) {
            int imported = 0;
            int skipped = 0;
            
            while (fileScanner.hasNextLine()) {
                String line = fileScanner.nextLine().trim();
                if (line.isEmpty() || line.startsWith("Account,")) continue;
                
                String[] parts = line.split(",", 5);
                if (parts.length >= 3) {
                    String account = parts[0].trim().toLowerCase();
                    String username = parts.length > 1 ? parts[1].trim() : "";
                    String password = parts[2].trim();
                    String website = parts.length > 3 ? parts[3].trim() : "";
                    String notes = parts.length > 4 ? parts[4].trim() : "";
                    
                    if (!password.isEmpty()) {
                        String encryptedPassword = encrypt(password);
                        PasswordEntry entry = new PasswordEntry(encryptedPassword, website, username, notes);
                        passwordStorage.put(account, entry);
                        imported++;
                    } else {
                        skipped++;
                    }
                } else {
                    skipped++;
                }
            }
            
            System.out.println("✓ Import completed!");
            System.out.println("Imported: " + imported + " entries");
            if (skipped > 0) {
                System.out.println("Skipped: " + skipped + " invalid entries");
            }
            
        } catch (FileNotFoundException e) {
            System.out.println("File not found: " + filename);
        } catch (Exception e) {
            System.out.println("Import failed: " + e.getMessage());
        }
    }
    
    private static void changeMasterPassword() {
        System.out.println("\n=== CHANGE MASTER PASSWORD ===");
        System.out.println("⚠️  This will re-encrypt all your data with a new master password.");
        
        System.out.print("Enter current master password: ");
        String currentPassword = System.console() != null ? 
            new String(System.console().readPassword()) : scanner.nextLine();
        
        try {
            if (!hashPassword(currentPassword).equals(masterPasswordHash)) {
                System.out.println("Incorrect current password.");
                return;
            }
        } catch (Exception e) {
            System.out.println("Authentication error: " + e.getMessage());
            return;
        }
        
        String newPassword = "";
        String confirmPassword = "";
        
        while (true) {
            System.out.print("Enter new master password: ");
            newPassword = System.console() != null ? 
                new String(System.console().readPassword()) : scanner.nextLine();
            
            if (!isPasswordStrong(newPassword)) {
                System.out.println("Password too weak. Please use at least 8 characters with letters, numbers, and symbols.");
                continue;
            }
            
            System.out.print("Confirm new master password: ");
            confirmPassword = System.console() != null ? 
                new String(System.console().readPassword()) : scanner.nextLine();
            
            if (newPassword.equals(confirmPassword)) {
                break;
            } else {
                System.out.println("Passwords don't match. Please try again.");
            }
        }
        
        try {
            // Update master password hash
            masterPasswordHash = hashPassword(newPassword);
            
            // Generate new encryption key
            secretKey = generateKey();
            
            // Re-encrypt all passwords
            Map<String, PasswordEntry> tempStorage = new HashMap<>();
            for (Map.Entry<String, PasswordEntry> entry : passwordStorage.entrySet()) {
                String account = entry.getKey();
                PasswordEntry pe = entry.getValue();
                String decryptedPassword = decrypt(pe.encryptedPassword);
                pe.encryptedPassword = encrypt(decryptedPassword);
                tempStorage.put(account, pe);
            }
            passwordStorage = tempStorage;
            
            // Save updated data
            saveMasterData();
            
            System.out.println("✓ Master password changed successfully!");
            System.out.println("All data has been re-encrypted with the new password.");
            
        } catch (Exception e) {
            System.out.println("Error changing master password: " + e.getMessage());
        }
    }
    
    private static boolean exitProgram() {
        System.out.print("\nSave changes and exit? (y/n): ");
        String confirm = scanner.nextLine().trim().toLowerCase();
        
        if (confirm.equals("y") || confirm.equals("yes")) {
            saveDataToFile();
            System.out.println("\n" + "=".repeat(50));
            System.out.println("    Thank you for using Enhanced Password Manager!");
            System.out.println("         Your data has been saved securely.");
            System.out.println("    Remember to keep your master password safe!");
            System.out.println("=".repeat(50));
            return false;
        }
        return true;
    }
    
    // Utility methods
    private static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    private static boolean isPasswordStrong(String password) {
        return password.length() >= 8 &&
               password.matches(".*[A-Z].*") &&
               password.matches(".*[a-z].*") &&
               password.matches(".*[0-9].*") &&
               password.matches(".*[!@#$%^&*()\\-_=+\\[\\]{}|;:,.<>?].*");
    }
    
    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
    
    private static String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }
    
    private static String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedData = cipher.doFinal(decodedData);
        return new String(decryptedData);
    }
    
    private static void saveMasterData() throws Exception {
        String keyData = masterPasswordHash + "|" + Base64.getEncoder().encodeToString(secretKey.getEncoded());
        Files.write(Paths.get(KEY_FILE), keyData.getBytes());
    }
    
    private static void saveDataToFile() {
        try {
            StringBuilder data = new StringBuilder();
            
            for (Map.Entry<String, PasswordEntry> entry : passwordStorage.entrySet()) {
                String account = entry.getKey();
                PasswordEntry pe = entry.getValue();
                
                data.append(account).append("|")
                    .append(pe.encryptedPassword).append("|")
                    .append(pe.website).append("|")
                    .append(pe.username).append("|")
                    .append(pe.notes).append("|")
                    .append(pe.created).append("|")
                    .append(pe.lastModified).append("|")
                    .append(pe.accessCount).append("\n");
            }
            
            Files.write(Paths.get(DATA_FILE), data.toString().getBytes());
            
        } catch (Exception e) {
            System.out.println("Error saving data: " + e.getMessage());
        }
    }
    
    private static void loadPasswordData() throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(DATA_FILE));
        
        for (String line : lines) {
            if (line.trim().isEmpty()) continue;
            
            String[] parts = line.split("\\|", 8);
            if (parts.length >= 8) {
                String account = parts[0];
                PasswordEntry entry = new PasswordEntry(parts[1], parts[2], parts[3], parts[4]);
                entry.created = LocalDateTime.parse(parts[5]);
                entry.lastModified = LocalDateTime.parse(parts[6]);
                entry.accessCount = Integer.parseInt(parts[7]);
                
                passwordStorage.put(account, entry);
            }
        }
    }
    
    private static void saveGeneratedPassword(String password) {
        System.out.print("Enter account name for this password: ");
        String account = scanner.nextLine().trim();
        
        if (account.isEmpty()) {
            System.out.println("Account name cannot be empty.");
            return;
        }
        
        System.out.print("Username/Email (optional): ");
        String username = scanner.nextLine().trim();
        
        System.out.print("Website/URL (optional): ");
        String website = scanner.nextLine().trim();
        
        System.out.print("Notes (optional): ");
        String notes = scanner.nextLine().trim();
        
        try {
            String encryptedPassword = encrypt(password);
            PasswordEntry entry = new PasswordEntry(encryptedPassword, website, username, notes);
            passwordStorage.put(account.toLowerCase(), entry);
            System.out.println("✓ Password saved successfully for " + account);
        } catch (Exception e) {
            System.out.println("Error saving password: " + e.getMessage());
        }
    }
    
    private static char getRandomChar(String chars, SecureRandom random) {
        return chars.charAt(random.nextInt(chars.length()));
    }
    
    private static String shuffleString(String input, SecureRandom random) {
        List<String> characters = Arrays.asList(input.split(""));
        Collections.shuffle(characters, random);
        return String.join("", characters);
    }
    
    private static String evaluateStrength(String password) {
        int score = 0;
        
        if (password.length() >= 8) score++;
        if (password.length() >= 12) score++;
        if (password.length() >= 16) score++;
        if (password.matches(".*[A-Z].*")) score++;
        if (password.matches(".*[a-z].*")) score++;
        if (password.matches(".*[0-9].*")) score++;
        if (password.matches(".*[!@#$%^&*()\\-_=+\\[\\]{}|;:,.<>?].*")) score++;
        if (password.length() >= 20) score++;
        
        if (score >= 7) return "Very Strong";
        if (score >= 5) return "Strong";
        if (score >= 3) return "Medium";
        return "Weak";
    }
    
    private static double calculateEntropy(String password) {
        int charset = 0;
        if (password.matches(".*[a-z].*")) charset += 26;
        if (password.matches(".*[A-Z].*")) charset += 26;
        if (password.matches(".*[0-9].*")) charset += 10;
        if (password.matches(".*[!@#$%^&*()\\-_=+\\[\\]{}|;:,.<>?].*")) charset += 32;
        
        return password.length() * Math.log(charset) / Math.log(2);
    }
    
    private static void suggestSimilarEntries(String input) {
        System.out.println("\nDid you mean one of these?");
        int suggestions = 0;
        
        for (String account : passwordStorage.keySet()) {
            if (account.contains(input) || input.contains(account)) {
                System.out.println("- " + account);
                suggestions++;
                if (suggestions >= 3) break;
            }
        }
        
        if (suggestions == 0) {
            System.out.println("No similar entries found.");
        }
    }
    
    private static void clearScreen() {
        // Print multiple newlines to simulate screen clear
        for (int i = 0; i < 3; i++) {
            System.out.println();
        }
    }
}