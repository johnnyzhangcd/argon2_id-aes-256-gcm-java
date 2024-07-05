import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import com.google.zxing.WriterException;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;

public class AESHandler {

    private static final int T_LEN = 128;
    private static final int KEY_SIZE = 256;
    private static final String ALGORITHM = "AES/GCM/NoPadding";

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("请选择操作类型 (encrypt : 1/decrypt : 2):");
        String operation = scanner.nextLine();

        if (operation.equalsIgnoreCase("1")) {
            encrypt(scanner);
        } else if (operation.equalsIgnoreCase("2")) {
            decrypt(scanner);
        } else {
            System.out.println("无效的操作类型。");
        }
    }

    private static void encrypt(Scanner scanner) throws Exception {
        System.out.println("请输入要加密的文本:");
        String plaintext = scanner.nextLine();
        System.out.println("请输入密码:");
        String password = scanner.nextLine();

        int saltLength = 16;
        int parallelism = 4;
        int memory = 512000;
        int iterations = 10;

        byte[] salt = new byte[saltLength];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withParallelism(parallelism)
                .withMemoryAsKB(memory)
                .withIterations(iterations);
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());

        byte[] key = new byte[KEY_SIZE / 8];
        generator.generateBytes(password.toCharArray(), key);

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(T_LEN, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] encryptedData = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(ciphertext, 0, encryptedData, iv.length, ciphertext.length);

        String base64Ciphertext = Base64.getEncoder().encodeToString(encryptedData);

        String params = iterations + ":" + memory + ":" + parallelism + ":" + Base64.getEncoder().encodeToString(salt) + ":" + base64Ciphertext;
        System.out.println("加密后的Base64文本: " + params);

        generateQRCode(params, "qrcode.png");
    }

    private static void decrypt(Scanner scanner) throws Exception {
        System.out.println("请输入Base64编码的加密文本:");
        String base64Params = scanner.nextLine();
        System.out.println("请输入密码:");
        String password = scanner.nextLine();

        String[] parts = base64Params.split(":");
        int iterations = Integer.parseInt(parts[0]);
        int memory = Integer.parseInt(parts[1]);
        int parallelism = Integer.parseInt(parts[2]);
        byte[] salt = Base64.getDecoder().decode(parts[3]);
        byte[] encryptedData = Base64.getDecoder().decode(parts[4]);

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withParallelism(parallelism)
                .withMemoryAsKB(memory)
                .withIterations(iterations);
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());

        byte[] key = new byte[KEY_SIZE / 8];
        generator.generateBytes(password.toCharArray(), key);

        byte[] iv = new byte[12];
        byte[] ciphertext = new byte[encryptedData.length - 12];

        System.arraycopy(encryptedData, 0, iv, 0, iv.length);
        System.arraycopy(encryptedData, iv.length, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(T_LEN, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);

        byte[] plaintext = cipher.doFinal(ciphertext);

        System.out.println("解密后的文本: " + new String(plaintext, StandardCharsets.UTF_8));
    }

    private static void generateQRCode(String text, String filePath) throws IOException, WriterException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, 200, 200);
        Path path = Paths.get(filePath);
        MatrixToImageWriter.writeToPath(bitMatrix, "PNG", path);
    }
}
