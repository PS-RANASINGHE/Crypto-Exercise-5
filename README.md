# Crypto-Exercise-5

# Week 5 (https://github.com/ouspg/CryptoCourse/tree/main/5.Hard_problems_and_RSA)

## Task 1

### Task 1.1

In this task we will be completing a simple task in RSA encryption. The code which is mentioned below is a simple yet powerful demonstration of RSA encryption using OpenSSL. RSA which is named after its inventors Rivest, Shamir, and Adleman is a public-key cryptosystem widely used for secure data transmission. It is based on the mathematical challenge of factoring large numbers a problem for which no efficient solution has been found.

When considering the first line of my code provided below an RSA private key of 2048 bits is generated. The number 2048 refers to the size of the key where you should be note that with larger sizes being more secure but slower. This key is stored in a file which I named as  private_key.pem. The ‘pem’ extension stands for Privacy Enhanced Mail in which is a file format for storing and sending cryptographic keys.

The second line extracts the public key from the private key. In, RSA the private key is kept secret while the public key can be freely distributed. This is because RSA like other public key cryptosystems  relies on the principle of asymmetric cryptography. This means that two different keys are used which is as you guessed a public key for encryption and a private key for decryption. The public key can be freely distributed because it is used to encrypt data. Anyone  in which  who looks into can use the public key to encrypt a message but once it is encrypted the message can only be decrypted using the corresponding private key. As mentioned the private key is kept secret because it is used to decrypt data. If, someone else had access to your private key they could decrypt any messages that were encrypted using your public key. This would compromise the security of the communication. So in my code the public key is saved in a file named public_key.pem.


The third line encrypts a message using the public key. The message ‘Hello, World!’ is piped into the openssl rsautl command, which performs the encryption. The -pubin flag tells OpenSSL to use the public key for encryption. The encrypted message is then I have saved in a file named encrypted_message.bin.
This, code makes sure that the message can only be decrypted by someone with the corresponding private key. This is the essence of RSA encryption: even if someone intercepts the encrypted message in which they cannot decrypt it without the private key.

In addition to encryption RSA can also be used for digital signatures. A digital signature is a way of ensuring the integrity and authenticity of a message. It involves creating a hash of the message, encrypting the hash with the sender’s private key, and sending it along with the message. The recipient can then decrypt the hash using the sender’s public key and compare it to their own hash of the message. If the hashes match, the message is verified.

```console

# Generate an RSA private key of 2048 bits
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Extract the public key
openssl rsa -pubout -in private_key.pem -out public_key.pem

# Encrypt a message using the public key
echo 'Hello, World!' | openssl rsautl -encrypt -pubin -inkey public_key.pem > encrypted_message.bin

```


The code below mentioned is a the step by step approach of the above script with the results generated. Here it should be noted that I have decrypted the message also using the key in order to make sure the encryption has done correctly.

```Console
PSR@archlinux ~ % openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

....+++++++++++++++++++++++++++++++++++++++*..........+...+.....+....+.....+...+.............+......+...+.....+.+++++++++++++++++++++++++++++++++++++++*.+.+.........+.........+........+.......+...........+................+...+........+...+......................+..+......+......+..........+......+........+.+.....+......+.........+....+..+.......+..+.........+.+........+...+.......+..+.........+.......+.....+...+.+...+..+.........+.......+.....+..........+..+...............+.+............+..+............+.+...........................+..+.........+.+...+...+.....+.......+..+...+.......+...+..................+...+............+........+......+...+.+...........+...+......+.+...+...........+.......+..................+......+........+.+......+...+..+....+......+......+..+...+...+.....................+......+...+....+......+...........+......+..........+..+.......+...+..+....+.....+.+.....+.++++++
..+++++++++++++++++++++++++++++++++++++++*..........+......+...............+...+...+..+...+...+....+++++++++++++++++++++++++++++++++++++++*.....+....+...+..+...+...+.........+......+...+......+...+...............+................+.....+....+...+...............+............+...........+..........+.....+......+.+.........+........+.+..+....+...++++++
PSR@archlinux ~ % openssl rsa -pubout -in private_key.pem -out public_key.pem

writing RSA key
PSR@archlinux ~ % cat private_key.pem
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC28Fm5NZtVSY7e
D1h9DuBUZsm/ccJQZHzr5vXWreoJX9XwdMDgDmooXes813wS4fSXTyXCamDKFCjK
AyfvxslubVF+dC6YjEwoQ1I86CcOqNXLYYK3gSEf7A+YbjfatmMScCvQqMrnZsGP
SRKn9D0uWPUWxyWhxTNEmpPmGctbdpP2PeYWYuIOFy117cluFC0+TKuS0GcoiVZK
eYQN5M+b19F+IBvviF0b7djue6PBoFGHo7UtpIiVznvnJN6ZNL4d+JrC6ZKecfiL
/9+ptkJapdfk7VXwfJJ0kCzZws/gGFikj9PqdPlsOO/t+g1cHsYj+LHj6fl5Nf2A
O86IJS/jAgMBAAECggEAF44aF3FyF0i55xjVvYCJXQTBLG/i48QUm7Fo7SQGkv9u
hiAaZ58jhyAUtohOdwX2Hvd3drGI1exDlkNSxJp1fE0CJcSi7Ux/T93fPG1t/gK6
SI49LRCo6bnVBj0G3xgF6K1dzue0/JesC52Ok+asbAfTQwQQceR45ff7XDDtENEb
hgFpP+C0uNb0Enl9uF1+plxiqaQftPdnZf+FgCHIksg1z9YgR6Gx4dFFEgD9npGL
+vzT9YFVKrr+HTu0i4jGQNiPZFMmBVW9LPLZ6oUvv/iThd2ktnjXb223ztcFtLX7
G+WeozvwCs3+/AfipaeKT+amxUHqxd0UnPbbSgHIAQKBgQDl8s2gmUeDaheRcewC
63amV6PmgfxQglahavAjufiZiskktUzLwbSKaxvbBlYFNsICBGyZPm3RoUq5G57/
j5vnhn4hH/8OvEX+7t4wA2eDIZ0RgXiDsolZEZ/ydfezgbXrV5o2nqL79VfuxVNZ
2ZF90FcbdpS+PbW+S3qyQ0/34wKBgQDLqiDD5RLbanlTIgIp9bFaESz6dVOlRsyv
0zT+WW95SrB1yCUNmKkT2sG8CV1A/v5ziXCwzcncGd67R5t6Xx93PQisXRQoV3Zk
Seab0COwu2X0p4cgmW4biqznHNMmFa0EK8N/FbYxYQj3Bn7ZFNEWSY90uauw+kAN
4GM9VytoAQKBgE2+0AMyj9lAr4M/bzp1fgIzs3imDjbyOnQNAfAyWnkfUW6V1cc2
UOJT4HEnLUJKB0JDWKxfTSYJUIhRbGqflWisMkzk0oma4leVT44QOJk/bimTCroM
TR/OM7P4aq1Id8eAMOWysQxbIUXbdZj1VJmjLTBd4WCI4L/cKTnIRGtdAoGBAJHf
PLCSdjspu9RLW3lqPKjh/HE3b73FQ/37LM2wiSM618DEpaVjXlaWLITdwCk5ek6O
dmRsQNSgwuMomre/Qe5JjNjHohRy8J1MQRwArE99Kb1d8G7s9exMGyM9hg6VH+MI
5XE0v9YGRkGIKXqaaleoQFO+WLbdxtspiGr68GABAoGAc87bGOn6DFgN7UxNVtBB
Z22rQymORtKubyRBp7TFfFEhakXmzdxcOcMfcqCNLidKpQasfPUsb+zUPYGmv+wq
e2bvavxmiMRjPPRxnbSihbAuINL3nIeVJEENDghSa6Xg04/sOz3AFkzSnxRD9vLN
zWoCcYm5C1n6SZA8WeDyCTw=
-----END PRIVATE KEY-----
PSR@archlinux ~ % cat public_key.pem 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtvBZuTWbVUmO3g9YfQ7g
VGbJv3HCUGR86+b11q3qCV/V8HTA4A5qKF3rPNd8EuH0l08lwmpgyhQoygMn78bJ
bm1RfnQumIxMKENSPOgnDqjVy2GCt4EhH+wPmG432rZjEnAr0KjK52bBj0kSp/Q9
Llj1FsclocUzRJqT5hnLW3aT9j3mFmLiDhctde3JbhQtPkyrktBnKIlWSnmEDeTP
m9fRfiAb74hdG+3Y7nujwaBRh6O1LaSIlc575yTemTS+HfiawumSnnH4i//fqbZC
WqXX5O1V8HySdJAs2cLP4BhYpI/T6nT5bDjv7foNXB7GI/ix4+n5eTX9gDvOiCUv
4wIDAQAB
-----END PUBLIC KEY-----
PSR@archlinux ~ % 
PSR@archlinux ~ % 
PSR@archlinux ~ % echo 'Hello, World!' | openssl rsautl -encrypt -pubin -inkey public_key.pem > encrypted_message.bin~  
The command rsautl was deprecated in version 3.0. Use 'pkeyutl' instead.
PSR@archlinux ~ % echo 'Hello, World!' | openssl pkeyutl -encrypt -pubin -inkey public_key.pem -out encrypted_message.bin
PSR@archlinux ~ % ls
Desktop     encrypted_message.bin
Documents   private_key.pem
Downloads   public_key.pem
Music       encrypted_message.bin~
Pictures    
Public      
PSR@archlinux ~ % cat encrypted_message.bin
�4�CSAX�6U^PaANJ�r���9(�5��^K�9U�,nJ/�8:[_6�,��?_$O鸅(�~�QɅWD�ۛ,`4�Y��f�@U��{�3h�&�"��>GiI��b�6�>�����dg
�QA�n�2=[���l������oP+ף�h�u�SM��q�W�W�@
                                       Ծ���5//�(S�q���
                                                      �}%s���E����-���Nf�%j�R �5��-�����
�j�%+W�%

PSR@archlinux ~ % openssl rsautl -decrypt -inkey private_key.pem -in encrypted_message.bin

The command rsautl was deprecated in version 3.0. Use 'pkeyutl' instead.
Hello, World!
PSR@archlinux ~ % openssl pkeyutl -decrypt -inkey private_key.pem -in encrypted_message.bin
Hello, World!
PSR@archlinux ~ % 

```

### Task 1.2

Here I have created a file `message.txt` using `nano meesage.txt` and used the same key as mentioned earlier. The same public and primary key is used and commands used is mentioned below.

```console

# Sign the message using the private key
openssl dgst -sha256 -sign private_key.pem -out signature.sig message.txt

# Verify the signature using the public key
openssl dgst -sha256 -verify public_key.pem -signature signature.sig message.txt

```

The first command  will create a SHA-256 digest of `message.txt`, sign it using `private_key.pem`, and output the signature to `signature.sig`. The second code will verify the signature `signature.sig` of `message.txt` using `public_key.pem`. If the verification is successful, it will output `Verified OK`.


```console

PSR@archlinux ~ % nano message.txt
PSR@archlinux ~ % ls
PSR@archlinux ~ % cat message.txt          
Hello,World of Universe
PSR@archlinux ~ % 
PSR@archlinux ~ % openssl dgst -sha256 -sign private_key.pem -out signature.sig message.txt
PSR@archlinux ~ % openssl dgst -sha256 -verify public_key.pem -signature signature.sig message.txt
Verified OK
PSR@archlinux ~ % 
130 PSR@archlinux ~ % ls
Desktop    Templates       
Documents  message.txt
Downloads  private_key.pem
Music      public_key.pem
Pictures   signature.sha256
Public     signature.sig
PSR@archlinux ~ % 

```

## Task 2
 
### Task 2.1

The code I used to is as follows

```python

import os

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

signature_folder = "./files/signatures"
public_keys_folder = "./files/public_keys"
messages_file = "./files/messages.txt"

# Store filenames in dictionaries
signature_files = {f"signature{i}": os.path.join(signature_folder, f"signature{i}.sign") for i in range(1, 21)}
public_key_files = {f"public_key{i}": os.path.join(public_keys_folder, f"public_key{i}.pem") for i in range(1, 6)}

print("|Message row|Public key(s)|Signature file(s)|")
print("|---|---|---|")

with open(messages_file, 'r') as messages:
    for line_number, message in enumerate(messages, start=1):
        message = message.strip().encode('utf-8')
        matched_keys = []
        matched_signatures = []

        for key_name, key_path in public_key_files.items():
            with open(key_path, 'rb') as key_file:
                public_key_data = key_file.read()
                public_key = load_pem_public_key(public_key_data, backend=default_backend())

                for signature_name, signature_path in signature_files.items():
                    with open(signature_path, 'rb') as sig_file:
                        signature = sig_file.read()

                        try:
                            public_key.verify(
                                signature,
                                message,
                                padding.PKCS1v15(),
                                hashes.SHA256()
                            )
                            matched_keys.append(key_name)
                            matched_signatures.append(signature_name)
                        except InvalidSignature:
                            pass

        if matched_keys:
            keys_str = ', '.join(matched_keys)
            signatures_str = ', '.join(matched_signatures)
            print(f"|{line_number}|{keys_str}|{signatures_str}|")


```
The results are as follows

|Message row|Public key(s)|Signature file(s)|
|---|---|---|
|1|public_key2|signature6|
|2|public_key4|signature13|
|3|public_key3|signature2|
|4|public_key5|signature8|
|5|public_key4|signature11|
|7|public_key3|signature16|
|8|public_key1, public_key2|signature4, signature7|
|9|public_key5|signature14|
|10|public_key1|signature17|
|11|public_key5|signature3|
|12|public_key5|signature9|
|13|public_key2|signature10|
|14|public_key2|signature15|
|15|public_key3|signature1|
|16|public_key1|signature18|
|17|public_key4|signature12|
|18|public_key4|signature20|
|19|public_key1|signature5|
|20|public_key3|signature19|

![image](https://github.com/CryptoCourse-2024/cryptocourse-submissions-PS-RANASINGHE/assets/88810055/cc24e293-9e32-456a-8ed3-55e43fa2d864)


### Task 2.2

Imagine that you are using a vintage lock and key to secure your messages that is what using the textbook version of RSA for signing messages is like. It is charming but it leaves your system open to a Pandora's box of vulnerabilities.

**No Cushion for the Pushin':** Just like a lock without a proper fitting key, textbook RSA signing lacks padding mechanisms like PKCS#1. Without this cushion your RSA signatures are sitting ducks for attacks such as Bleichenbacher's attack in which can forge signatures faster than you can say "RSA".

**Déjà Vu Signatures:** Textbook RSA is like a broken record, producing the same signature for a given message over and over again. This predictability makes it a playground for replay attacks, where an attacker can reuse a valid signature to play dress-up as the original signer.

**Play-Doh Signatures:** Textbook RSA signatures are malleable, meaning they can be squished and reshaped by an attacker without needing the private key, leading to a valid signature for a related message. This can be exploited to create fraudulent transactions or modify the message's intended content.

**Short Keys, Big Problems:** Textbook RSA signatures often use smaller key lengths for the sake of computational efficiency. But just like a short key is easier to duplicate, smaller key lengths are more susceptible to brute force attacks. An attacker can factorize the modulus to recover the private key and forge signatures.

**Peeping Toms:** Without proper implementation protections, RSA operations can be spied on through side-channel attacks such as timing attacks or power analysis attacks. These attacks exploit information leaked during the execution of cryptographic operations to recover secret keys or other sensitive information.


To lock these vulnerabilities out, it is crucial to use standardized cryptographic libraries that implement RSA with proper padding schemes (like PKCS#1 v1.5 or OAEP) and employ adequate key lengths. Also, following best practices for key generation, storage, and usage, as well as employing measures to protect against side-channel attacks, can help fortify the security of your RSA-based systems. 



## Task 3

### Task 3.1
In order to complete the task we should
1. **Understand RSA:** RSA relies on the difficulty of factoring large semiprime numbers. The public key consists of the modulus n and the public exponent e, while the private key consists of the modulus n and the private exponent d.
2. **Message Crafting:** We craft a message with positive implications, starting with the prefix "-p".
3. **Forgery:** We compute a valid signature for our crafted message without Alice's private key by exploiting the mathematical properties of RSA.
4. **Verification:** Finally, we verify the signature using Alice's public key to confirm its validity.


```python
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Load Alice's public key
with open('files/alice.pub', 'r') as f:
    alice_public_key = RSA.import_key(f.read())

# Function to forge a signature for a given message
def forge_signature(message):
    # Craft a message with positive implications
    crafted_message = "_p " + message
    
    # Hash the crafted message using SHA256
    hashed_message = SHA256.new(crafted_message.encode())
    
    # Forge a signature using the public key exponent and modulus
    forged_signature = pow(int.from_bytes(hashed_message.digest(), byteorder='big'), alice_public_key.e, alice_public_key.n)
    
    return forged_signature

# Craft a message with positive implications
positive_message = "Mallory's performance exceeded expectations."

# Forge a signature for the positive message
forged_signature = forge_signature(positive_message)

# Print the forged message and signature
print("Forged Message:", positive_message)
print("Forged Signature:", forged_signature)

# Verify the signature using the PKCS#1 v1.5 signature scheme
h = SHA256.new(positive_message.encode())
try:
    pkcs1_15.new(alice_public_key).verify(h, (forged_signature,))
    print("Signature Verified: True")
except (ValueError, TypeError):
    print("Signature Verified: False")
```
In this code:

+ We load Alice's public key from the provided file.
+ We define a function forge_signature to forge a signature for a given message. This function crafts a message with positive implications, converts it to bytes, and then computes a forged signature using RSA's mathematical properties.
+ We craft a message with positive implications.
+ We forge a signature for the positive message using the forge_signature function.
+ We print the forged message and signature.
+ We verify the forged signature using Alice's public key to confirm its validity.

The results are as follows

![image](https://github.com/CryptoCourse-2024/cryptocourse-submissions-PS-RANASINGHE/assets/88810055/6b015911-4388-40d4-9461-66ffcbfe7f5c)


```console

Forged Message: Mallory's performance exceeded expectations.
Forged Signature: 46820661270163864097588889142892419729081320594203406571115127836929893918489650363120661382345183315417578732551079606576756084235488152547044852957954071238575008938852283507119465231829214774125792370465362985505366786156343859109291883179121424793288776569266385932649929094632803125183646421584818586165562383848883232118756954895866805047319685262473159205998195006055090722967905329535166927040608342976939703027944213707658147111106900945022307047384734845389696907575792802840981534013035269620890631505535721894564888553539516391583636442610159476598575900857624996688786031263489373512963774540009183973369303068571450119129000467335245932612050007124581406608985619790281266001170513123472882442168498057289470128555985941964493993558956671539036507012019325096811551130928168901634720133823315072789541059261931863465606511089300025127151751061373430747184736316955096770658937432642497815880888276856133553767359621584871310455080673258711005463017535024515236764489638505100215922421274744227835343513707366552734381934109678695469374992225462244355234805795610687843340332530272946793065486006570723111049504612898017590728003993730267563962229261225944133913778043859284876343119824718129992106675307565541755176748
Signature Verified: False
```
### Task 3.2

If we need to provide a valid and understandable message in its entirety for Alice to sign then what happen is the difficulty of the process increases significantly. This is because we cannot simply prepend a prefix to the message to change its implications But instead what we can do is  we can craft a message that conveys the desired meaning while still appearing legitimate to Alice.

Here is how the process changes and how the message length affects the difficulty.

+ Crafting a Meaningful Message: We need to carefully construct a message that appears plausible and aligns with the positive implications we desire. This may require understanding the context of the communication and ensuring that the message is coherent and believable.

+ Length of the Message: The longer the message, the more challenging it becomes to craft a meaningful message that also contains the desired implications. Longer messages provide more context and content for Alice to scrutinize, making it harder to hide any nefarious intent within the message.

+ RSA Signature Forging: Once we have crafted the message, we still need to forge a valid signature for it without Alice's cooperation. This involves exploiting the mathematical properties of RSA, but now we can't simply modify a small portion of the message; instead, we must craft the entire message to meet our objectives.

## Task 4

### Task 4.1

1. **Hard Problem**: The system is based on the integer factorization problem. This involves finding the prime factors of a given composite number. As the size of the number increases, the problem becomes exponentially harder due to the super-polynomial time complexity of the best known algorithms.

2. **Evidence of Hardness**: The evidence that integer factorization is hard comes from practical scenarios. Even with the most powerful supercomputers, factoring large integers (more than 200 digits) takes an impractical amount of time. This hardness is why it's used in RSA, a widely used public-key cryptosystem.

3. **Encryption Process**: The integer factorization problem is used to encrypt messages in the following way:
    - **Key Generation**: Two distinct prime numbers `p` and `q` are chosen. `n = p*q` is computed. The public key is `n`, and the private key is the pair `(p, q)`.
    - **Encryption**: A message `m` is converted into an integer `M` such that `0 <= M < n`. The ciphertext `C` is computed as `C = M^2 mod n`.
    - **Decryption**: The ciphertext `C` is decrypted by computing `M = C^(1/2) mod n` using the private key `(p, q)`.

This is a simplified version of a public key cryptosystem. It's not secure for practical use, but it serves as a good starting point for understanding the principles of public key cryptography. In practice, always use well-established and thoroughly tested cryptographic systems. Cryptography is a field where small mistakes can have big consequences, so it's always best to rely on proven solutions. Remember, the security of the system relies on the fact that while `n` can be easily computed from `p` and `q`, the reverse operation, i.e., computing `p` and `q` from `n`, is hard. This operation is easy if we know `p` and `q`, but hard otherwise. This is the essence of the integer factorization problem and its application in public key cryptography.

### Task 4.2

In the pseudocode that I have mentioned above the `generate_two_distinct_primes()` is a function in which that generates two distinct prime numbers. Also when considering the 2 funciotns `convert_message_to_integer()` and `convert_integer_to_message()` they convert a message to an integer and vice versa and next the `sqrt()` is a function in which that calculates the square root of a number.

Now let us discuss the complexity of the encryption process. The most computationally intensive step in the encryption process is the calculation of `C = (M**2) % n`. The time complexity of this operation is `O((log n)^2)` using fast exponentiation. Here `log n` is the number of bits in `n`. So here the encryption process is quite efficient.

So however the decryption process is more complex because it involves finding the square root of `C` modulo `n` in which requires knowledge of the prime factors `p` and `q`. Without knowing `p` and `q` this operation is as hard as factoring `n` in which is a computationally hard problem.

So it is important to note that this is one of the most simplified version of a public key cryptosystem and it is not adviced to play with this as it is less secure for practical use. So in practice you should always use well-established and thoroughly tested cryptographic systems. When considering cryptography, it is a field where small mistakes can have big consequences so it is always best to rely on proven solutions. Remember the security of a system created can be considered mostly relies on the fact that while `n` can be easily computed from `p` and `q` the reverse operation i.e. computing `p` and `q` from `n`, is hard. This operation is easy if we know `p` and `q`, but hard otherwise. This is the essence of the integer factorization problem and its application in public key cryptography.

This exercise provides a good starting point for understanding the principles of public key cryptography and the computational complexities involved in the encryption and decryption processes. It also highlights the importance of the hardness of the integer factorization problem in ensuring the security of public key cryptosystems.

### Task 4.3

 **Brute Force Attack**: The most straightforward attack is a brute force attack where the attacker tries all possible combinations of `p` and `q` until they find the pair that produces the public key `n`. However this attack is computationally infeasible for large `n` due to the time complexity of the integer factorization problem. The number of possible combinations of `p` and `q` is approximately `n/2` and testing each combination would require a prohibitive amount of computational resources.

 **Side-Channel Attacks**: Side-channel attacks exploit information gained from the physical implementation of the cryptosystem rather than brute force or theoretical weaknesses in the algorithms. For example when considering timing information, power consumption, electromagnetic leaks or even sound can provide an extra source of information in which can be exploited to break the system. If our cryptosystem is implemented in hardware or software it could potentially be vulnerable to such attacks. Mitigating side-channel attacks requires careful design and implementation of the cryptosystem, including measures such as constant-time operations and power analysis-resistant algorithms.

 **Man-in-the-Middle Attack**: In a man-in-the-middle attack, the attacker intercepts the public key `n` during transmission and replaces it with a key known to them. The sender then unknowingly encrypts the message using the attacker's key allowing the attacker to decrypt the intercepted messages. This attack can be mitigated by securely exchanging public keys, for example, through a secure key exchange protocol. However this requires an additional layer of security, such as a trusted third party or a secure channel for key exchange.

 **Quantum Computing Attacks**: If large-scale quantum computers become a reality, Shor's algorithm could be used to factor `n` efficiently, breaking the security of our cryptosystem. However, as of now, large-scale quantum computers capable of running Shor's algorithm do not exist. The development of quantum-resistant algorithms is an active area of research in cryptography.

 **Algorithmic Improvements**: The security of our system relies on the assumption that integer factorization is hard. If a new, efficient algorithm for integer factorization is discovered, it could potentially break the security of our system. This is a theoretical risk, but it is worth considering given the rapid pace of advancements in computer science and mathematics.

In conclusion, while our integer factorization-based public key cryptosystem provides a good starting point for understanding the principles of public key cryptography it is important to remember that it is a simplified version and not secure for practical use. In practice, always use well-established and thoroughly tested cryptographic systems. Cryptography is a field where small mistakes can have big consequences so it is always best to rely on proven solutions. This exercise provides a good starting point for understanding the principles of public key cryptography and the potential vulnerabilities involved in the encryption and decryption processes. It also highlights the importance of the hardness of the integer factorization problem in ensuring the security of public key cryptosystems.

### Task 4.4

The Integer Factorization Problem (IFP) is a well-known problem in the field of cryptography. It involves decomposing a composite number into its prime factors. The difficulty of this problem forms the basis of many cryptographic systems including RSA which is the one of the first public-key cryptosystems.
The RSA cryptosystem for instance relies on the difficulty of factoring large composite integers. The security of RSA is based on the assumption that while it is easy to multiply large prime numbers together to create a composite number, it is computationally difficult to do the reverse - that is to factor a large composite number into its prime components.

However the advent of quantum computing has posed a significant threat to RSA and other IFP-based cryptosystems. Shor’s algorithm, a quantum algorithm, can factorize integers and compute discrete logarithms in polynomial time. This means that if large-scale quantum computers become a reality, they could potentially break RSA and other similar cryptosystems.

There have also been attempts to build cryptographic systems that combine the difficulty of the IFP with other hard problems. For example, a digital signature scheme has been proposed that is based on the difficulty of both the IFP and the discrete logarithm problem for elliptic curves. This scheme is designed to provide long-term security and produce smaller signatures than existing schemes based on the IFP alone.

Despite these developments, it’s important to note that no efficient non-quantum algorithm for integer factorization is currently known for sufficiently large numbers. This means that IFP-based cryptosystems remain secure against classical computers. However, the potential future development of quantum computers capable of running Shor’s algorithm underscores the need for ongoing research into post-quantum cryptography.

In conclusion, the Integer Factorization Problem has been extensively used in cryptography, and while some proposed schemes have been theoretically broken by quantum algorithms, no practical breaks have been demonstrated due to the current limitations of quantum computing. The continued reliance on IFP-based schemes highlights the importance of this problem in the field of cryptography.

References - 

+ https://www.quora.com/How-can-I-write-pseudocode
+ https://study.com/learn/lesson/pseudocode-examples-how-to.html
+ https://www.geeksforgeeks.org/how-to-write-a-pseudo-code/
+ https://www.researchgate.net/publication/273011532_A_New_Approach_for_Complex_Encrypting_and_Decrypting_Data
+ https://www.sciencedirect.com/topics/computer-science/side-channel-attack
+ https://www.rapid7.com/fundamentals/man-in-the-middle-attacks/
+ https://www.geeksforgeeks.org/cryptanalysis-and-types-of-attacks/
+ https://ieeexplore.ieee.org/abstract/document/8924724
+ https://theses.hal.science/tel-00532638/


