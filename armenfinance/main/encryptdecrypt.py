from cryptography.fernet import Fernet

# encryption class
class EncryptDecryptKey:
    keyGen = Fernet.generate_key().decode('utf-8')

    # generate Keys
    def encryptionKey(self):
        return self.keyGen
    # save Key
    def saveKey(self, key):
        pass
    # query the database and load the key 
    def loadKey(self, key):
        load_key = self.key
        return load_key

    # encrypt data
    def preapare_encrypt_data(self, key):
        f = Fernet(key)
        return f


    # encrypt online_id

    ''' error  '''
    def encrypt_online_id(self, online_id, prepared_key=None):
        online_id = online_id.encode()
        id = self.prepared_key.encrypt(online_id)
        return id

    # encrypt password


# # instantiate the class
# encrypt = EncryptDecryptKey()

# # generate key to authenticate
# key = encrypt.encryptionKey()

# # data can now be encrypted as the key matches the generated key 
# prepared_key = encrypt.preapare_encrypt_data(key)

# # encrypt the data 
# online_id = '66d25a3e-4816-4bb6-9475-bc5fed412a55'.encode()
# password = 'ObEhSQlCA4gfRt'.encode()

# online_id_encrypted = prepared_key.encrypt(online_id)
# password_encrypted = prepared_key.encrypt(password)
# print(online_id_encrypted)
# print(password_encrypted)

# # decrypting data
# online_id_decrypted = prepared_key.decrypt(online_id_encrypted)
# password_decrypted = prepared_key.decrypt(password_encrypted)