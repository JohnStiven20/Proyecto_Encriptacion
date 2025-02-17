package proyecto_encriptado;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AESUtil {
    
    private static final String ALGORITMO = "AES/CBC/PKCS5Padding";

    public static String encriptar(String texto, SecretKey clave, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITMO);
        cipher.init(Cipher.ENCRYPT_MODE, clave, iv);
        byte[] encriptado = cipher.doFinal(texto.getBytes());
        return Base64.getEncoder().encodeToString(encriptado);
    }

    public static String desencriptar(String textoEncriptado, SecretKey clave, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITMO);
        cipher.init(Cipher.DECRYPT_MODE, clave, iv);
        byte[] decodificado = Base64.getDecoder().decode(textoEncriptado);
        byte[] desencriptado = cipher.doFinal(decodificado);
        return new String(desencriptado);
    }

    public static SecretKey generarClaveAES() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static IvParameterSpec generarIV() {
        byte[] iv = new byte[16];
        new java.security.SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
