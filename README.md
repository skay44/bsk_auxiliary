# bsk_auxiliary
Part of a simple Project created for Computer System Security course at Gdańsk institute of technology. This auxiliary app is a secure RSA key generator with a GUI. The application allows for generating public and private RSA key pairs. The private key is encrypted using a pin given by the user. The encryption is performed using AES-256 in CFB mode, with the AES key derived from the user pin via PBKDF2HMAC-SHA256.

### Building a project:
Using PyCharm is recommended. 

### Dependencies:
pip install cryptography==39.0.1 
sudo apt install python3-tk 
