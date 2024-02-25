import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SecurePasswordManager {

    private static final int SALT_LENGTH = 16; // Longitud de la sal en bytes
    private static final int HASH_ITERATIONS = 10000; // Número de iteraciones del hashing

    /**
     * Genera una sal aleatoria.
     *
     * @return La sal generada.
     */
    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt); // Genera bytes aleatorios de la sal
        return salt;
    }

    /**
     * Calcula el hash de una contraseña utilizando salting y hashing iterativo.
     *
     * @param password La contraseña a hashear.
     * @param salt     La sal a utilizar.
     * @return El hash de la contraseña.
     */
    private static String hashPassword(String password, byte[] salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256"); // Instancia del algoritmo de hash
            digest.reset();
            digest.update(salt); // Agrega la sal al algoritmo de hash

            byte[] hash = digest.digest(password.getBytes()); // Calcula el hash inicial de la contraseña

            // Aplica hashing iterativo
            for (int i = 0; i < HASH_ITERATIONS; i++) {
                digest.reset(); // Resetea el digest para cada iteración
                hash = digest.digest(hash); // Aplica el algoritmo de hash nuevamente
            }

            return Base64.getEncoder().encodeToString(hash); // Devuelve el hash en formato Base64
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String password = "mypassword";

        // Generar la sal
        byte[] salt = generateSalt();

        // Hashear la contraseña con salting y hashing iterativo
        String hashedPassword = hashPassword(password, salt);

        System.out.println("Contraseña original: " + password);
        System.out.println("Sal utilizada: " + Base64.getEncoder().encodeToString(salt));
        System.out.println("Contraseña hasheada: " + hashedPassword);
    }
}