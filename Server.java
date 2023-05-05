import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;

public class Server {
    private HashMap<String, String> registeredUsers;
    private HashMap<String, String> passwordPolicies;

    public Server() {
        registeredUsers = new HashMap<>();
        passwordPolicies = new HashMap<>();
        passwordPolicies.put("min_length", "8");
        passwordPolicies.put("min_uppercase", "1");
        passwordPolicies.put("min_lowercase", "1");
        passwordPolicies.put("min_digits", "1");
        passwordPolicies.put("min_special_chars", "1");
    }

    public void start(int port) throws Exception {
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server started on port " + port);

        while (true) {
            Socket socket = serverSocket.accept();
            new ServerThread(socket).start();
        }
    }

    public String register(String username, String password) throws Exception {
        if (!registeredUsers.containsKey(username)) {
            if (validatePassword(password)) {
                SecretKey key = generateKey(password);
                String encryptedPassword = encryptMessage(password, key);
                String hashedPassword = hashPassword(encryptedPassword);
                registeredUsers.put(username, hashedPassword);
                return "Registration successful";
            } else {
                throw new Exception("Password does not meet policy requirements");
            }
        } else {
            return "Username already exists";
        }
    }

    public String authenticate(String username, String password) throws Exception {
        if (registeredUsers.containsKey(username)) {
            String hashedPassword = registeredUsers.get(username);
            if (validatePassword(password)) {
                SecretKey key = generateKey(password);
                String encryptedPassword = encryptMessage(password, key);
                String inputHashedPassword = hashPassword(encryptedPassword);
                if (hashedPassword.equals(inputHashedPassword)) {
                    return "You are authenticated, Welcome " + username;
                }
            }
        }
        throw new Exception("Please enter correct username password");
    }

    private boolean validatePassword(String password) {
        if (password.length() < Integer.parseInt(passwordPolicies.get("min_length"))) {
            return false;
        }
        int uppercaseCount = 0, lowercaseCount = 0, digitCount = 0, specialCharCount = 0;
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                uppercaseCount++;
            } else if (Character.isLowerCase(c)) {
                lowercaseCount++;
            } else if (Character.isDigit(c)) {
                digitCount++;
            } else {
                specialCharCount++;
            }
        }
        if (uppercaseCount < Integer.parseInt(passwordPolicies.get("min_uppercase"))) {
            return false;
        }
        if (lowercaseCount < Integer.parseInt(passwordPolicies.get("min_lowercase"))) {
            return false;
        }
        if (digitCount < Integer.parseInt(passwordPolicies.get("min_digits"))) {
            return false;
        }
        if (specialCharCount < Integer.parseInt(passwordPolicies.get("min_special_chars"))) {
            return false;
        }
        return true;
    }

    private String hashPassword(String password) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(password.getBytes("UTF-8"));
        byte[] digest = messageDigest.digest();
        return Base64.getEncoder().encodeToString(digest);
    }

    private SecretKey generateKey(String password) throws Exception {
        String salt = "some_salt_here"; // Use a proper salt, store it securely and use the same salt for both encryption and decryption
        int iterationCount = 65536;
        int keyLength = 128;
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterationCount, keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    private String encryptMessage(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    private class ServerThread extends Thread {
        private Socket socket;

        public ServerThread(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                InputStream input = socket.getInputStream();
                OutputStream output = socket.getOutputStream();
                int length = ByteBuffer.wrap(input.readNBytes(4)).getInt(); // Reading the message length
                byte[] buffer = new byte[length];
                int bytesRead = input.read(buffer);
                String encryptedMessage = new String(buffer, 0, bytesRead);
                String message = decryptMessage(encryptedMessage, generateKey("some_password_here"));
                String[] parts = message.split(":");
                String action = parts[0];
                System.out.println(parts[0]);
                String username = parts[1];
                String password = parts[2];

                String response = "";
                if (action.equals("register")) {
                    response = register(username, password);
                } else if (action.equals("authenticate")) {
                    response = authenticate(username, password);
                }

                String encryptedResponse = encryptMessage(response, generateKey("some_password_here"));
                byte[] encryptedResponseBytes = encryptedResponse.getBytes("UTF-8");
                int responseLength = encryptedResponseBytes.length;
                output.write(ByteBuffer.allocate(4).putInt(responseLength).array()); // Sending the response length
                output.write(encryptedResponseBytes);
                output.flush();

                input.close();
                output.close();
                socket.close();
            } catch (Exception e) {
                try {
                    OutputStream output = socket.getOutputStream();
                    String response = e.getMessage();
                    String encryptedResponse = encryptMessage(response, generateKey("some_password_here"));
                    byte[] encryptedResponseBytes = encryptedResponse.getBytes("UTF-8");
                    int responseLength = encryptedResponseBytes.length;
                    output.write(ByteBuffer.allocate(4).putInt(responseLength).array()); // Sending the response length
                    output.write(encryptedResponseBytes);
                    output.flush();
                    output.close();
                    socket.close();
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        }

    }

    public static void main(String[] args) {
        Server server = new Server();
        try {
            server.start(5676);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String decryptMessage(String encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedMessage = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedMessage = cipher.doFinal(decodedMessage);
        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }

}
