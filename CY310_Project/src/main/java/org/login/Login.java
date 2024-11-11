package org.login;

import java.io.File;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Scanner;

public class Login {
    static {
        try {
            // Explicitly load the SQLite JDBC driver
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            System.out.println("SQLite JDBC driver not found: " + e.getMessage());
        }
    }

    private static final String DB_PATH = Paths.get(System.getProperty("user.home"), ".sqlite", "db", "login.db").toString();

    public static void connect() {
        // Check if the database exists, otherwise create it
        File dbFile = new File(DB_PATH);
        if (!dbFile.exists()) {
            // Create the necessary directories
            new File(dbFile.getParent()).mkdirs();
            System.out.println("Database not found. Creating new database...");
            createNewDatabase(DB_PATH);
            createTable(DB_PATH);
        } else {
            System.out.println("Database found.");
        }
    }

    // Method to create the database (will create the file automatically if it doesn't exist)
    private static void createNewDatabase(String url) {
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + url)) {
            if (conn != null) {
                System.out.println("A new database has been created.");
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    // Method to create a table in the database if it doesn't exist
    private static void createTable(String url) {
        String sql = "CREATE TABLE IF NOT EXISTS users (\n"
                + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                + " username TEXT NOT NULL UNIQUE,\n"
                + " password TEXT NOT NULL,\n"
                + " salt TEXT NOT NULL\n"
                + ");";

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + url);
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table 'users' created (or already exists).");
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    // Method to hash the password with a salt
    private static String hashPassword(String password, String salt) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(salt.getBytes());
        byte[] hash = digest.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash); // Return Base64 encoded hash
    }

    // Method to generate a random salt
    private static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16]; // 16 bytes for salt
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt); // Encode salt in Base64
    }

    // Method to insert a new user with hashed password
    public static void addUser(String username, String password) {
        // Generate a salt
        String salt = generateSalt();

        try {
            // Hash the password with the salt
            String hashedPassword = hashPassword(password, salt);

            // Insert the user into the database
            String sql = "INSERT INTO users (username, password, salt) VALUES (?, ?, ?)";
            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
                 PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, username);
                pstmt.setString(2, hashedPassword);
                pstmt.setString(3, salt);
                pstmt.executeUpdate();
                System.out.println("User added successfully.");
            } catch (SQLException e) {
                System.out.println("Error inserting user: " + e.getMessage());
            }
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error hashing password: " + e.getMessage());
        }
    }

    // Method to verify the user login
    public static boolean verifyUser(String username, String inputPassword) {
        String sql = "SELECT password, salt FROM users WHERE username = ?";

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    String storedHash = rs.getString("password");
                    String storedSalt = rs.getString("salt");

                    // Hash the input password with the stored salt
                    String inputHash = hashPassword(inputPassword, storedSalt);

                    // Compare the hashes
                    if (storedHash.equals(inputHash)) {
                        return true;  // Login successful
                    }
                }
            } catch (SQLException e) {
                System.out.println("Error during query execution: " + e.getMessage());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        } catch (SQLException e) {
            System.out.println("Error connecting to the database: " + e.getMessage());
        }
        return false;  // Login failed
    }

    public static void login() {
        Scanner scanner = new Scanner(System.in);
        boolean runLoginMenu = true;
        String username;
        String inputPassword;

        System.out.println("Please select an option:");

        while (runLoginMenu) {
            System.out.println("1. Login as existing user\n" +
                    "2. Create User\n" +
                    "0. Exit\n");

            String loginMenuSelection = scanner.nextLine();

            switch (loginMenuSelection) {
                case "1":
                    System.out.println("Enter username: ");
                    username = scanner.nextLine();
                    System.out.println("Enter password: ");
                    inputPassword = scanner.nextLine();

                    boolean loginSuccess = verifyUser(username, inputPassword);
                    if (loginSuccess) {
                        System.out.println("Login successful.");
                        runLoginMenu = false;  // Exit the menu loop after successful login
                    } else {
                        System.out.println("Login failed.");
                    }
                    break;

                case "2":
                    System.out.println("Enter username: ");
                    username = scanner.nextLine();
                    System.out.println("Enter password: ");
                    inputPassword = scanner.nextLine();

                    addUser(username, inputPassword);
                    break;

                case "0":
                    System.out.println("Goodbye.");
                    System.exit(0);  // Exit the application

                default:
                    System.out.println("Please enter a valid option.");
                    break;
            }
        }
    }
}
