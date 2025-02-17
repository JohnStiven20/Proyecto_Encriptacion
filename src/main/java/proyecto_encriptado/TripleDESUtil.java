package proyecto_encriptado;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class TripleDESUtil {
    
    private static final String ALGORITMO = "DESede";

    public static String encriptar(String texto, SecretKey clave) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITMO);
        cipher.init(Cipher.ENCRYPT_MODE, clave);
        byte[] encriptado = cipher.doFinal(texto.getBytes());
        return Base64.getEncoder().encodeToString(encriptado);
    }

    public static String desencriptar(String textoEncriptado, SecretKey clave) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITMO);
        cipher.init(Cipher.DECRYPT_MODE, clave);
        byte[] decodificado = Base64.getDecoder().decode(textoEncriptado);
        byte[] desencriptado = cipher.doFinal(decodificado);
        return new String(desencriptado);
    }

    public static SecretKey generarClave3DES() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
        keyGenerator.init(168);
        return keyGenerator.generateKey();
    }

}
