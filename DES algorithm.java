DES algorithm

import javax.crypto.Cipher; 
import javax.crypto.spec.IvParameterSpec; 
import java.security.SecureRandom; 
import java.util.Base64; 
import javax.crypto.spec.SecretKeySpec; 
import java.util.*; 
class Des { 
private static final String ALGORITHM = "DES/CBC/PKCS5Padding"; 
private static final String KEY_ALGORITHM = "DES"; 
private Cipher encryptCipher; 
private Cipher decryptCipher; 
public Des(byte[] key, byte[] iv) throws Exception { 
SecretKeySpec keySpec = new SecretKeySpec(key, KEY_ALGORITHM); 
IvParameterSpec ivSpec = new IvParameterSpec(iv); 
encryptCipher = Cipher.getInstance(ALGORITHM); 
encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec); 
decryptCipher = Cipher.getInstance(ALGORITHM); 
decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec); 
} 
public String encrypt(String str) throws Exception { 
byte[] utf8 = str.getBytes("UTF-8"); 
byte[] encrypted = encryptCipher.doFinal(utf8); 
return Base64.getEncoder().encodeToString(encrypted); 
} 
public String decrypt(String str) throws Exception { 
byte[] dec = Base64.getDecoder().decode(str); 
byte[] decrypted = decryptCipher.doFinal(dec); 
return new String(decrypted, "UTF-8"); 
} 
public static void main(String[] args) throws Exception { 
Scanner sc=new Scanner(System.in); 
final String secretText = sc.nextLine(); 
System.out.println("Secret Text: " + secretText); 
// Generate a random key securely 
SecureRandom random = new SecureRandom(); 
byte[] key = new byte[8]; 
random.nextBytes(key); 
// Generate a random initialization vector 
byte[] iv = new byte[8]; 
random.nextBytes(iv); 
Des encrypter = new Des(key, iv); 
String encrypted = encrypter.encrypt(secretText); 
System.out.println("Encrypted Value: " + encrypted); 
String decrypted = encrypter.decrypt(encrypted); 
System.out.println("Decrypted: " + decrypted); 
sc.close(); 
} 
}

RSA algorithm


import java.math.*; 
import java.util.*; 
class RSA { 
public static void main(String args[]) 
{ 
int p, q, n, z, d = 0, e, i; 
int msg = 12; 
double c; 
BigInteger msgback; 
p = 3; 
q = 11; 
n = p * q; 
z = (p - 1) * (q - 1); 
System.out.println("the value of z = " + z); 
for (e = 2; e < z; e++) { 
if (gcd(e, z) == 1) { 
} 
} 
break; 
System.out.println("the value of e = " + e); 
for (i = 0; i <= 9; i++) { 
int x = 1 + (i * z); 
if (x % e == 0) { 
d = x / e; 
break; 
} 
} 
System.out.println("the value of d = " + d); 
c = (Math.pow(msg, e)) % n; 
System.out.println("Encrypted message is : " + c); 
BigInteger N = BigInteger.valueOf(n); 
BigInteger C = BigDecimal.valueOf(c).toBigInteger(); 
msgback = (C.pow(d)).mod(N); 
System.out.println("Decrypted message is : " 
+ msgback); 
} 
static int gcd(int e, int z) 
{ 
} 
} 
if (e == 0) 
return z; 
else 
return gcd(z % e, e);


hiffine man algorithm




import java.util.*; 
class DiffieHellmanAlgorithmExample { 
public static void main(String[] args) 
{ 
long P, G, x, a, y, b, ka, kb; 
Scanner sc = new Scanner(System.in); 
System.out.println("Both the users should be agreed upon the public keys G and P"); 
System.out.println("Enter value for public key G:"); 
G = sc.nextLong(); 
System.out.println("Enter value for public key P:"); 
P = sc.nextLong(); 
System.out.println("Enter value for private key a selected by user1:"); 
a = sc.nextLong(); 
System.out.println("Enter value for private key b selected by user2:"); 
b = sc.nextLong(); 
x = calculatePower(G, a, P); 
y = calculatePower(G, b, P); 
ka = calculatePower(y, a, P); 
kb = calculatePower(x, b, P); 
System.out.println("Secret key for User1 is:" + ka); 
System.out.println("Secret key for User2 is:" + kb); 
} 
private static long calculatePower(long x, long y, long P) 
{ 
} 
} 
long result = 0; 
if (y == 1){ 
return x; 
} 
else{ 
result = ((long)Math.pow(x, y)) % P; 
return result;

MD 5 


import hashlib 
def hash_message(message): 
hash_obj = hashlib.md5() 
hash_obj.update(message.encode()) 
return hash_obj.hexdigest() 
user_input = input("ENTER MESSAGE: ") 
hashed_output = hash_message(user_input) 
print("The hexadecimal equivalent of hash is:", hashed_output)


sha 1


import hashlib 
import hashlib 
def hash_message(message): 
hash_obj = hashlib.sha1() 
hash_obj.update(message.encode()) 
return hash_obj.hexdigest() 
test = input(‘Enter Message: ‘) 
print("The SHA-1 hash of the message is:", hash_message(text)) 



digital signature


from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives import serialization 
private_key = rsa.generate_private_key( 
public_exponent=65537, 
key_size=2048, 
backend=default_backend() 
) 
pem = private_key.private_bytes( 
encoding=serialization.Encoding.PEM, 
format=serialization.PrivateFormat.PKCS8, 
encryption_algorithm=serialization.NoEncryption() 
) 
print("Private Key in PEM Format:") 
print(pem.decode()) 
public_key = private_key.public_key() 
print("Key Details:") 
print("Key size:", private_key.key_size) 
print("Public Exponent:", private_key.public_numbers().e) 
print("Modulus:", private_key.public_numbers().n)
