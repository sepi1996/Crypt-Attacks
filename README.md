# Crypto-Attacks
This repository contains some basic attacks. We can find:
##### BreakRepeatingByteKey
In this attack we will break an encrypted text in flow using a single-byte key in length
##### BreakRepeatingKey
In this attack we will break an encrypted text in flow using a key. This type of encryption is also known as Cesar encryption. To do this we will use text properties such as editing distance.
##### ByteAtATime: 
In this attack we will break an encrypted text using a secret key algorithm, in this case AES in ECB mode. For this we will rely on the lack of diffusion that we obtain when applying the algorithm to plain text
##### PaddingOracleAttack
In this attack we will break an encrypted text using a secret key algorithm, in this case AES in CBC mode. For this we will rely on the PKSC7 fill algorithm, and an Oracle which tells us when a text is PKCS7 compliant.
##### Hastas'sBroadcastAttack
In this attack we will break an encrypted text using a public key algorithm, in this case RSA. For this we will take advantage of a weak public key exponent and the Chinese residue Theorem.
##### RSASignatureAttack
Through this attack, discovered by the cryptographer Bleichenbacher's, it is possible under certain circumstances to easily falsify an RSA signature. This depends on an implementation error, as it does not verify a certain condition while the RSA signature is verified
##### BleichenbacherCCAAttack
In this attack we will break an encrypted text using a public key algorithm, in this case RSA. For this we will build on the following document where the attack is explained in more detail: http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
