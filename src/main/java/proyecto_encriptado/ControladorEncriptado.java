package proyecto_encriptado;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.ResourceBundle;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.mindrot.jbcrypt.BCrypt;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.MenuButton;
import javafx.scene.control.MenuItem;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;

public class ControladorEncriptado implements Initializable {

    @FXML
    private MenuButton menuAlgoritmos;
    @FXML
    private MenuItem menuItemAesCbc;
    @FXML
    private MenuItem menuItemTripleDes;
    @FXML
    private TextArea textAreaEncriptado;
    @FXML
    private TextArea textAreaDesncriptado;
    @FXML
    private TextField textField;
    @FXML
    private Button encriptar;
    @FXML
    private Button descriptar;
    @FXML
    private RadioButton radioButtonCriptografia;
    @FXML
    private RadioButton radioButtonBCrypt;
    @FXML
    private HBox hBoxCampoCriptofrafia;
    @FXML
    private HBox hBoxCampoBCrypt;
    @FXML
    private Label labelClaveGuardada;

    private SecretKey claveAES;
    private IvParameterSpec ivAES;
    private SecretKey clave3DES;
    private String claveBCryptGuardada;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        hBoxCampoBCrypt.setVisible(false);
        hBoxCampoCriptofrafia.setVisible(true);
    }

    @FXML
    public void radioButton() {
        limpiarCampos(); // Restablece los campos cada vez que se cambia de opción

        if (radioButtonBCrypt.isSelected()) {
            hBoxCampoBCrypt.setVisible(true);
            hBoxCampoCriptofrafia.setVisible(false);
        } else if (radioButtonCriptografia.isSelected()) {
            hBoxCampoBCrypt.setVisible(false);
            hBoxCampoCriptofrafia.setVisible(true);
        }
    }

    @FXML
    public void seleccionarAesCbc() {
        menuAlgoritmos.setText(menuItemAesCbc.getText());
    }

    @FXML
    public void seleccionarTripleDes() {
        menuAlgoritmos.setText(menuItemTripleDes.getText());
    }

    @FXML
    public void encriptarTexto() {
        if (radioButtonBCrypt.isSelected()) {
            guardarClaveBCrypt();
            return;
        }

        String texto = textAreaEncriptado.getText();
        String claveIngresada = textField.getText();

        if (texto.isBlank() || claveIngresada.isBlank()) {
            mostrarError("Ingrese un texto y una clave antes de encriptar.");
            return;
        }

        try {
            String algoritmoSeleccionado = menuAlgoritmos.getText();
            String textoEncriptado = "";

            if ("AES / CBC".equals(algoritmoSeleccionado)) {
                claveAES = generarClaveDesdeTexto(claveIngresada, 32);
                ivAES = AESUtil.generarIV();
                textoEncriptado = AESUtil.encriptar(texto, claveAES, ivAES);
            } else if ("3DES".equals(algoritmoSeleccionado)) {
                clave3DES = generarClaveDesdeTexto(claveIngresada, 24);
                textoEncriptado = TripleDESUtil.encriptar(texto, clave3DES);
            }

            textAreaDesncriptado.setText(textoEncriptado);
            textAreaEncriptado.clear();

        } catch (Exception e) {
            mostrarError("Error al encriptar: " + e.getMessage());
        }
    }

    @FXML
    public void desencriptarTexto() {
        if (radioButtonBCrypt.isSelected()) {
            verificarClaveBCrypt();
            return;
        }

        String textoEncriptado = textAreaDesncriptado.getText();
        String claveIngresada = textField.getText();

        if (textoEncriptado.isBlank() || claveIngresada.isBlank()) {
            mostrarError("Ingrese un texto encriptado y la clave antes de desencriptar.");
            return;
        }

        try {
            String algoritmoSeleccionado = menuAlgoritmos.getText();
            String textoDesencriptado = "";

            if ("AES / CBC".equals(algoritmoSeleccionado)) {
                if (ivAES == null) {
                    mostrarError("No hay IV almacenado. Primero encripte un texto.");
                    return;
                }
                claveAES = generarClaveDesdeTexto(claveIngresada, 32);
                textoDesencriptado = AESUtil.desencriptar(textoEncriptado, claveAES, ivAES);
            } else if ("3DES".equals(algoritmoSeleccionado)) {
                clave3DES = generarClaveDesdeTexto(claveIngresada, 24);
                textoDesencriptado = TripleDESUtil.desencriptar(textoEncriptado, clave3DES);
            }

            textAreaEncriptado.setText(textoDesencriptado);
            textAreaDesncriptado.clear();

        } catch (Exception e) {
            mostrarError("Error al desencriptar: " + e.getMessage());
        }
    }

    private void guardarClaveBCrypt() {
        String claveIngresada = textAreaEncriptado.getText();
        if (claveIngresada.isBlank()) {
            mostrarError("Ingrese una clave antes de guardarla.");
            return;
        }

        claveBCryptGuardada = BCrypt.hashpw(claveIngresada, BCrypt.gensalt(12));

        labelClaveGuardada.setText("Clave guardada: " + claveBCryptGuardada);
        textAreaDesncriptado.setText(claveBCryptGuardada);
        textAreaEncriptado.clear();
    }

    private void verificarClaveBCrypt() {
        String claveIngresada = textAreaEncriptado.getText();
        if (claveIngresada.isBlank()) {
            mostrarError("Ingrese una clave para verificar.");
            return;
        }

        if (BCrypt.checkpw(claveIngresada, claveBCryptGuardada)) {
            mostrarMensaje("Clave correcta.");
        } else {
            mostrarMensaje("Clave incorrecta.");
        }
    }

    /**
     * Método para limpiar todos los campos cuando se cambia entre Criptografía Simétrica y BCrypt.
     */
    private void limpiarCampos() {
        textAreaEncriptado.clear();
        textAreaDesncriptado.clear();
        labelClaveGuardada.setText("Clave guardada:");
        claveBCryptGuardada = null;
    }

    private SecretKey generarClaveDesdeTexto(String claveTexto, int longitud) throws Exception {
        byte[] claveBytes = claveTexto.getBytes(StandardCharsets.UTF_8);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        claveBytes = sha.digest(claveBytes);
        claveBytes = Arrays.copyOf(claveBytes, longitud);

        return new SecretKeySpec(claveBytes, longitud == 32 ? "AES" : "DESede");
    }

    private void mostrarError(String mensaje) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setContentText(mensaje);
        alert.setHeaderText(null);
        alert.showAndWait();
    }

    private void mostrarMensaje(String mensaje) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Mensaje");
        alert.setHeaderText(null);
        alert.setContentText(mensaje);
        alert.showAndWait();
    }
}
