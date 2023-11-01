import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;


public class SecureDataCryptor {

    private static SecretKey secretKey;
    private static Map<String, String> passwordMap = new HashMap<>();
    private static Map<String, String> userRoles = new HashMap<>();
    private static String loggedInUser = null;
    private static byte[] salt = new byte[]{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};

    private static final String DATABASE_URL = "jdbc:sqlite:securedata.db";

    public static void main(String[] args) {
        initializeDatabase();
        SwingUtilities.invokeLater(() -> {
            JFrame frame = createMainFrame();
            centerWindow(frame);
            frame.setVisible(true);
            Connection connection = null;
            try {
                connection = DriverManager.getConnection("jdbc:sqlite:securedata.db");
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }

            try
            {
                // create a database connection
                connection = DriverManager.getConnection("jdbc:sqlite:sample.db");
                Statement statement = connection.createStatement();
                statement.setQueryTimeout(30);  // set timeout to 30 sec.

                statement.executeUpdate("drop table if exists person");
                statement.executeUpdate("create table person (id integer, name string)");
                statement.executeUpdate("insert into person values(1, 'leo')");
                statement.executeUpdate("insert into person values(2, 'yui')");
                ResultSet rs = statement.executeQuery("select * from person");
                while(rs.next())
                {
                    // read the result set
                    System.out.println("name = " + rs.getString("name"));
                    System.out.println("id = " + rs.getInt("id"));
                }
            }
            catch(SQLException e)
            {
                // if the error message is "out of memory",
                // it probably means no database file is found
                System.err.println(e.getMessage());
            }
            finally
            {
                try
                {
                    if(connection != null)
                        connection.close();
                }
                catch(SQLException e)
                {
                    // connection close failed.
                    System.err.println(e.getMessage());
                }
            }
        

        });
    }

    private static void initializeDatabase() {
        try (Connection conn = DriverManager.getConnection(DATABASE_URL)) {
            String createUserTableSQL = "CREATE TABLE IF NOT EXISTS users (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "username TEXT NOT NULL," +
                    "password TEXT NOT NULL)";
            try (Statement stmt = conn.createStatement()) {
                stmt.execute(createUserTableSQL);
            }

            String createRoleTableSQL = "CREATE TABLE IF NOT EXISTS roles (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "username TEXT NOT NULL," +
                    "role TEXT NOT NULL)";
            try (Statement stmt = conn.createStatement()) {
                stmt.execute(createRoleTableSQL);
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static JFrame createMainFrame() {
        JFrame frame = new JFrame("Secure Data Application");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);

        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout());

        JTextField inputField = new JTextField();
        JTextArea resultArea = new JTextArea();
        JButton encryptButton = createButton("Encrypt");
        JButton decryptButton = createButton("Decrypt");
        JButton saveButton = createButton("Save Data");
        JButton loadButton = createButton("Load Data");
        JButton setPasswordButton = createButton("Set Password");
        JButton loginButton = createButton("Log In/Register");

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridLayout(2, 3));
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);
        buttonPanel.add(saveButton);
        buttonPanel.add(loadButton);
        buttonPanel.add(setPasswordButton);
        buttonPanel.add(loginButton);

        panel.add(inputField, BorderLayout.NORTH);
        panel.add(resultArea, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        addEncryptButtonActionListener(encryptButton, inputField, resultArea);
        addDecryptButtonActionListener(decryptButton, inputField, resultArea);
        addSaveButtonActionListener(saveButton, inputField, resultArea);
        addLoadButtonActionListener(loadButton, resultArea);
        addSetPasswordButtonActionListener(setPasswordButton, resultArea);
        addLoginButtonActionListener(loginButton, resultArea);

        frame.add(panel);
        return frame;
    }

    private static JButton createButton(String label) {
        return new JButton(label);
    }

    private static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private static String hashPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 10000;
        int keyLength = 256;

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = factory.generateSecret(spec).getEncoded();

        return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
    }

    private static boolean verifyPassword(String providedPassword, String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String[] parts = storedPassword.split(":");
        byte[] salt = Base64.getDecoder().decode(parts[0]);
        String hashedPassword = hashPassword(providedPassword, salt);

        return storedPassword.equals(hashedPassword);
    }

    private static void addEncryptButtonActionListener(JButton encryptButton, JTextField inputField, JTextArea resultArea) {
        encryptButton.addActionListener(e -> {
            if (loggedInUser == null) {
                showErrorMessage("Please log in or register.", resultArea);
                return;
            }

            if (!userHasRole(loggedInUser, "USER")) {
                showErrorMessage("You do not have permission to encrypt data.", resultArea);
                return;
            }

            String password = getPasswordFromUser("Enter your password:");
            if (password == null) {
                showErrorMessage("Password entry canceled.", resultArea);
                return;
            }

            try {
                String text = inputField.getText();
                byte[] encryptedDataWithIV = encryptDataGCM(text);
                String encryptedText = Base64.getEncoder().encodeToString(encryptedDataWithIV);
                resultArea.setText("Encrypted Text:\n" + encryptedText);
            } catch (Exception ex) {
                showErrorMessage("Encryption failed: " + ex.getMessage(), resultArea);
            }
        });
    }

    private static void addDecryptButtonActionListener(JButton decryptButton, JTextField inputField, JTextArea resultArea) {
        decryptButton.addActionListener(e -> {
            if (loggedInUser == null) {
                showErrorMessage("Please log in or register.", resultArea);
                return;
            }

            if (!userHasRole(loggedInUser, "USER")) {
                showErrorMessage("You do not have permission to decrypt data.", resultArea);
                return;
            }

            String password = getPasswordFromUser("Enter your password:");
            if (password == null) {
                showErrorMessage("Password entry canceled.", resultArea);
                return;
            }

            try {
                String encryptedText = inputField.getText();
                byte[] encryptedDataWithIV = Base64.getDecoder().decode(encryptedText);
                String originalText = decryptDataGCM(encryptedDataWithIV);
                resultArea.setText("Original Text:\n" + originalText);
            } catch (Exception ex) {
                showErrorMessage("Decryption failed: " + ex.getMessage(), resultArea);
            }
        });
    }

    private static void addSaveButtonActionListener(JButton saveButton, JTextField inputField, JTextArea resultArea) {
        saveButton.addActionListener(e -> {
            if (loggedInUser == null) {
                showErrorMessage("Please log in or register.", resultArea);
                return;
            }

            if (!userHasRole(loggedInUser, "USER")) {
                showErrorMessage("You do not have permission to save data.", resultArea);
                return;
            }

            try {
                String dataToSave = inputField.getText();
                JFileChooser fileChooser = new JFileChooser();
                if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                    File file = fileChooser.getSelectedFile();
                    saveData(loggedInUser, dataToSave, file);
                    resultArea.setText("Data saved.");
                }
            } catch (Exception ex) {
                showErrorMessage("Error: " + ex.getMessage(), resultArea);
            }
        });
    }

    private static void addLoadButtonActionListener(JButton loadButton, JTextArea resultArea) {
        loadButton.addActionListener(e -> {
            if (loggedInUser == null) {
                showErrorMessage("Please log in or register.", resultArea);
                return;
            }

            if (!userHasRole(loggedInUser, "USER")) {
                showErrorMessage("You do not have permission to load data.", resultArea);
                return;
            }

            try {
                JFileChooser fileChooser = new JFileChooser();
                if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                    File file = fileChooser.getSelectedFile();
                    String loadedData = loadData(loggedInUser, file);
                    if (loadedData != null) {
                        resultArea.setText("Loaded Data:\n" + loadedData);
                    } else {
                        resultArea.setText("Data not found for the user.");
                    }
                }
            } catch (Exception ex) {
                showErrorMessage("Error: " + ex.getMessage(), resultArea);
            }
        });
    }

    private static void addSetPasswordButtonActionListener(JButton setPasswordButton, JTextArea resultArea) {
        setPasswordButton.addActionListener(e -> {
            if (loggedInUser == null) {
                showErrorMessage("Please log in or register.", resultArea);
                return;
            }

            if (!userHasRole(loggedInUser, "ADMIN")) {
                showErrorMessage("You do not have permission to set passwords.", resultArea);
                return;
            }

            String newPassword = getPasswordFromUser("Enter a new password:");
            if (newPassword == null) {
                showErrorMessage("Password entry canceled.", resultArea);
                return;
            }

            if (!checkPasswordStrength(newPassword)) {
                showErrorMessage("Password does not meet complexity policy.", resultArea);
                return;
            }

            try {
                generateSecretKey(newPassword);
                passwordMap.put(loggedInUser, newPassword);
                resultArea.setText("Password updated.");
            } catch (Exception ex) {
                showErrorMessage("Error: " + ex.getMessage(), resultArea);
            }
        });
    }

    private static void addLoginButtonActionListener(JButton loginButton, JTextArea resultArea) {
        loginButton.addActionListener(e -> {
            if (loggedInUser == null) {
                String username = JOptionPane.showInputDialog(null, "Username:");
                if (username != null) {
                    String password = getPasswordFromUser("Password:");
                    if (password != null) {
                        try {
                            if (passwordMap.containsKey(username) && verifyPassword(password, passwordMap.get(username))) {
                                loggedInUser = username;
                                resultArea.setText("Logged in as: " + loggedInUser);
                            } else {
                                showErrorMessage("Incorrect username or password.", resultArea);
                            }
                        } catch (NoSuchAlgorithmException ex) {
                            throw new RuntimeException(ex);
                        } catch (InvalidKeySpecException ex) {
                            throw new RuntimeException(ex);
                        }
                    } else {
                        // Handle the case where the user canceled the password input
                        showErrorMessage("Password entry canceled.", resultArea);
                    }
                } else {
                    // Handle the case where the user canceled the username input
                    showErrorMessage("Username entry canceled.", resultArea);
                }
            } else {
                loggedInUser = null;
                resultArea.setText("Logged out.");
            }
        });
    }

    private static String getPasswordFromUser(String prompt) {
        return JOptionPane.showInputDialog(null, prompt);
    }

    private static void showErrorMessage(String message, JTextArea resultArea) {
        JOptionPane.showMessageDialog(null, message, "Error", JOptionPane.ERROR_MESSAGE);
        resultArea.setText(message);
    }

    private static void generateSecretKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private static byte[] encryptDataGCM(String data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        byte[] encryptedDataWithIV = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, encryptedDataWithIV, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, encryptedDataWithIV, iv.length, encryptedBytes.length);

        return encryptedDataWithIV;
    }

    private static String decryptDataGCM(byte[] encryptedDataWithIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        byte[] iv = Arrays.copyOfRange(encryptedDataWithIV, 0, 12);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] decryptedBytes = cipher.doFinal(Arrays.copyOfRange(encryptedDataWithIV, 12, encryptedDataWithIV.length));
        return new String(decryptedBytes);
    }

    private static void saveData(String username, String data, File file) throws IOException {
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(data);
        }
    }

    private static String loadData(String username, File file) throws IOException {
        if (file.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                return sb.toString().trim();
            }
        }
        return null;
    }

    private static boolean checkPasswordStrength(String password) {
        if (password.length() < 8) {
            return false;
        }
        boolean hasUpperCase = false;
        boolean hasLowerCase = false;
        boolean hasDigit = false;
        boolean hasSpecialChar = false;
        String specialChars = "!@#$%^&*()_-+=<>?";

        for (char character : password.toCharArray()) {
            if (Character.isUpperCase(character)) {
                hasUpperCase = true;
            } else if (Character.isLowerCase(character)) {
                hasLowerCase = true;
            } else if (Character.isDigit(character)) {
                hasDigit = true;
            } else if (specialChars.contains(String.valueOf(character))) {
                hasSpecialChar = true;
            }
        }

        return hasUpperCase && hasLowerCase && hasDigit && hasSpecialChar;
    }

    private static void centerWindow(JFrame frame) {
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        int centerX = (int) (screenSize.getWidth() - frame.getWidth()) / 2;
        int centerY = (int) (screenSize.getHeight() - frame.getHeight()) / 2;
        frame.setLocation(centerX, centerY);
    }

    private static void addUserRole(String username, String role) {
        userRoles.put(username, role);
    }

    private static boolean userHasRole(String username, String role) {
        if (userRoles.containsKey(username)) {
            return userRoles.get(username).equals(role);
        }
        return false;
    }


}
