import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.spec.KeySpec;
import java.util.Base64;

public class Client {
    private static final String SERVER_ADDRESS = "127.0.0.1";
    private static final int SERVER_PORT = 5676;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                createAndShowGUI();
            }
        });
    }

    public static void createAndShowGUI() {
        JFrame frame = new JFrame("Forum Client");
        frame.setSize(300, 200);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel panel = new JPanel();
        panel.setLayout(null);

        JLabel usernameLabel = new JLabel("Username:");
        usernameLabel.setBounds(10, 10, 80, 25);
        panel.add(usernameLabel);

        JTextField usernameTextField = new JTextField(20);
        usernameTextField.setBounds(100, 10, 160, 25);
        panel.add(usernameTextField);
        JLabel passwordLabel = new JLabel("Password:");
        passwordLabel.setBounds(10, 40, 80, 25);
        panel.add(passwordLabel);

        JPasswordField passwordField = new JPasswordField(20);
        passwordField.setBounds(100, 40, 160, 25);
        panel.add(passwordField);

        JButton registerButton = new JButton("Register");
        registerButton.setBounds(10, 80, 100, 25);
        panel.add(registerButton);

        JButton loginButton = new JButton("Login");
        loginButton.setBounds(160, 80, 100, 25);
        panel.add(loginButton);

        JTextArea statusTextArea = new JTextArea();
        statusTextArea.setEditable(false);
        statusTextArea.setBounds(10, 120, 250, 50);
        panel.add(statusTextArea);

        registerButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String username = usernameTextField.getText();
                String password = new String(passwordField.getPassword());
                try {
                    String result = register(username, password);
                    statusTextArea.setText(result);
                } catch (Exception ex) {
                    statusTextArea.setText(ex.getMessage());
                }
            }
        });

        loginButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String username = usernameTextField.getText();
                String password = new String(passwordField.getPassword());
                try {
                    String result = authenticate(username, password);
                    statusTextArea.setText(result);
                } catch (Exception ex) {
                    statusTextArea.setText(ex.getMessage());
                }
            }
        });

        frame.add(panel);
        frame.setVisible(true);
    }

    private static String register(String username, String password) throws Exception {
        String message = "register:" + username + ":" + password;
        String response = sendToServer(message);
        if (response.equals("Registration successful")) {
            return response;
        } else {
            throw new Exception(response);
        }
    }

    private static String authenticate(String username, String password) throws Exception {
        String message = "authenticate:" + username + ":" + password;
        String response = sendToServer(message);
        if (response.startsWith("You are authenticated, Welcome")) {
            return response;
        } else {
            throw new Exception(response);
        }
    }

    private static String sendToServer(String message) throws Exception {
        Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
        InputStream input = socket.getInputStream();
        OutputStream output = socket.getOutputStream();
        SecretKey key = generateKey("some_password_here"); // Replace with a password that is only known to the client and the server
        String encryptedMessage = encryptMessage(message, key);
        byte[] encryptedMessageBytes = encryptedMessage.getBytes("UTF-8");
        int messageLength = encryptedMessageBytes.length;
        output.write(ByteBuffer.allocate(4).putInt(messageLength).array()); // Sending the message length
        output.write(encryptedMessageBytes);
        output.flush();
        int length = ByteBuffer.wrap(input.readNBytes(4)).getInt(); // Reading the message length
        byte[] buffer = new byte[length];
        int bytesRead = input.read(buffer);
        String response = new String(buffer, 0, bytesRead);
        String decryptedResponse = decryptMessage(response, key);
        input.close();
        output.close();
        socket.close();
        return decryptedResponse;
    }


    private static SecretKey generateKey(String password) throws Exception {
        String salt = "some_salt_here"; // Use a proper salt, store it securely and use the same salt for both encryption and decryption
        int iterationCount = 65536;
        int keyLength = 128;
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterationCount, keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    private static String encryptMessage(String message, SecretKey key) throws
            Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    private static String decryptMessage(String encryptedMessage, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedMessage = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedMessage);
    }
}
