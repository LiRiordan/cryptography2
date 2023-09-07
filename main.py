import os
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass
import base64
from os.path import join

route = r'C:\Documents\folder_containing_file_to_encrypt'
file = r'file_to_encrypt.txt'
store_folder = r'Make_this_a_folder_on_a_memory_stick'
hmac_file = r'a_file_on_the_memory_stick.txt'
store_file = r'another_file_on_the_memory_stick.txt'

with open(join(store_folder,store_file),'rb') as text:
    contents = text.read()
    salt = contents.split(b'\n')[0]
    key_2 = contents.split(b'\n')[1]
    hashed = contents.split(b'\n')[2]

with open(join(route,hmac_file),'rb') as text:
    signature = text.read()

with open(join(route,file),'rb') as text:
    message = text.read()
h = hmac.HMAC(key_2,hashes.SHA256())
h.update(message)
try:
    h.verify(signature)
except:
    print('Caution! It appears the original file has been corrupted')

password = getpass('Enter the password: ').encode('utf-8')
if not bcrypt.checkpw(password,hashed):
    quit()

kdf = PBKDF2HMAC(hashes.SHA256(),length = 32, salt = salt, iterations = 100000)
key_1 = base64.urlsafe_b64encode(kdf.derive(password))

Decryptor = Fernet(key_1)
with open(join(route,file),'rb') as text:
    contents = text.read()
    decrypted = Decryptor.decrypt(contents)
with open(join(route,file),'wb') as text:
    text.write(decrypted)

Response = input('Are you done yet? ')

salt_2 = os.urandom(16)
key_3 = os.urandom(16)

kdf = PBKDF2HMAC(hashes.SHA256(),length = 32, salt = salt_2, iterations = 100000)
key_4 = base64.urlsafe_b64encode(kdf.derive(password))

Rerun = Fernet(key_4)


with open(join(route,file),'rb') as text:
    contents = text.read()
    encrypted1 = Rerun.encrypt(contents)
with open(join(route,file),'wb') as text:
    text.write(encrypted1)

t = hmac.HMAC(key_3,hashes.SHA256())
with open(join(route,file),'rb') as text:
    message_2 = text.read()
t.update(message_2)
signature_2 = t.finalize()   ### needs to be relogged as IV changes output

bs = bcrypt.gensalt()
hashed_2 = str(bcrypt.hashpw(password,bs)).encode('utf-8')

with open(join(store_folder,store_file),'wb') as text:
    text.write(salt_2 + b'\n' + key_3 + b'\n' + hashed_2)
with open(join(route,hmac_file),'wb') as text:
    text.write(signature_2)

os.system('echo Done')



