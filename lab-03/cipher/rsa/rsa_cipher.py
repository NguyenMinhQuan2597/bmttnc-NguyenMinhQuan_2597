import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from ui.rsa import Ui_MainWindow
import requests

import rsa, os

if not os.path.exists('cipher/rsa/keys'):
    os.makedirs('cipher/rsa/keys')

class RSACipher:
    def __init__(self):
        pass

    def generate_keys(self):
        (public_key, private_key) = rsa.newkeys(1024)
        with open('cipher/rsa/keys/publicKey.pem', 'wb') as p:
            p.write(public_key.save_pkcs1('PEM'))
        with open('cipher/rsa/keys/privateKey.pem', 'wb') as p:
            p.write(private_key.save_pkcs1('PEM'))

    def load_keys(self):
        with open('cipher/rsa/keys/publicKey.pem', 'rb') as p:
            public_key = rsa.PublicKey.load_pkcs1(p.read())
        with open('cipher/rsa/keys/privateKey.pem', 'rb') as p:
            private_key = rsa.PrivateKey.load_pkcs1(p.read())
        return private_key, public_key

    def encrypt(self, message, key):
        return rsa.encrypt(message.encode('ascii'), key)

    def decrypt(self, ciphertext, key):
        try:
            return rsa.decrypt(ciphertext, key).decode('ascii')
        except:
            return False

    def sign(self, message, key):
        return rsa.sign(message.encode('ascii'), key, 'SHA-1')

    def verify(self, message, signature, key):
        try:
            return rsa.verify(message.encode('ascii'), signature, key,) == 'SHA-1'
        except:
            return False
        
class MyApp(QMainWindow):
    def __init__(self):
        super().__Ui_MainWindow()
        self.ui = Ui_MainWindow()
        self.ui. setupUi(self)
        self.ui. btn_gen_keys.clicked.connect(self.call_api_gen_keys)
        self.ui. btn_encrypt.clicked.connect(self.call_api_encrypt)
        self.ui. btn_decrypt.clicked.connect(self.call_api_decrypt)
        self.ui. btn_sgin.clicked.connect(self.call_api_sgin)
        self.ui. btn_verify.clicked.connect(self.call_api_verify)
        
    def call_api_gen_keys(self):
        url = "https://127.0.0.1:5000/api/rsa/generate_keys"
        try:
            response = requests.get(url)
            if response. status_code ==200:
                data = response.json()
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText(data["message"])
                msg.exec_()
            else:
                print("Error While calling API")
        except requests.exceptions. RequestException as e:
            print("Error: %s" % e.message)
    
    def call_api_encrypt(self):
        url = "https://127.0.0.1:5000/api/rsa/enceypt"
        payload = {
            "message": self.ui.txt_plain_text.toPlainText(),
            "key_type": "public"    
        }
        try:
            response = requests.post(url, json=payload)
            if response. status_code ==200:
                data = response.json()
                self.ui.txt_cipher_text.setText(data["encrypted_message"])
                
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Encrypted Successfully")
                msg.exec_()
            else:
                print("Error While calling API")
        except requests.exceptions. RequestException as e:
            print("Error: %s" % e.message)
            
def call_api_decrypt(self):
        url = "https://127.0.0.1:5000/api/rsa/deceypt"
        payload = {
            "message": self.ui.txt_cipher_text.toPlainText(),
            "key_type": "private"    
        }
        
        try:
            response = requests.post(url, json=payload)
            if response. status_code ==200:
                data = response.json()
                self.ui.txt_plain_text.setText(data["decrypted_message"])
                
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Decrypted Successfully")
                msg.exec_()
            else:
                print("Error While calling API")
        except requests.exceptions. RequestException as e:
            print("Error: %s" % e.message)

def call_api_sgin(self):
        url = "https://127.0.0.1:5000/api/rsa/sgin"
        payload = {
            "message": self.ui.txt_info.toPlainText(),    
        }
        
        try:
            response = requests.post(url, json=payload)
            if response. status_code ==200:
                data = response.json()
                self.ui.txt_sgin.setText(data["sginature"])
                
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Signed Successfully")
                msg.exec_()
            else:
                print("Error While calling API")
        except requests.exceptions. RequestException as e:
            print("Error: %s" % e.message)
                
def call_api_verify(self):
    url = "https://127.0.0.1:5000/api/rsa/verify"
    payload = {
            "message": self.ui.txt_info.toPlainText(), 
            "signature": self.ui.txt_sgin.toPlainText()   
            }
    try:
        response = requests.post(url, json=payload)
        if response. status_code ==200:
            data = response.json()
            if (data["is_verifief"]):
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Verified Successfully")
                msg.exec_()
            else:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Verified Fail")
                msg.exec_()   
        else:   
            print("Error While calling API")
    except requests.exceptions. RequestException as e:
                print("Error: %s" % e.message)
                
if __name__ == "__main__": 
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())                           
