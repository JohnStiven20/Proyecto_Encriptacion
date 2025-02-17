module proyecto_encriptado {
    requires javafx.controls;
    requires javafx.fxml;
    requires jbcrypt;

    opens proyecto_encriptado to javafx.fxml;
    exports proyecto_encriptado;
}
