# myinfo-v4
To generate private and public keys, you can follow below steps.

Use below commands
1) First generate Private Key and maintain secretly using below command

openssl ecparam -name prime256v1 -genkey -noout -out sign_private.key
openssl ecparam -name prime256v1 -genkey -noout -out enc_private.key


2) once generated then run below command to generate Private Key to be used by myinfo code 

openssl pkcs8 -topk8 -inform pem -in sign_private.key -outform pem -nocrypt -out sign_private.pem
openssl pkcs8 -topk8 -inform pem -in enc_private.key -outform pem -nocrypt -out enc_private.pem

3) Then using above pem file generate public key.

openssl req -x509 -nodes -days 730 -sha256 -key sign_private.pem -out sign_public.pem
openssl req -x509 -nodes -days 730 -sha256 -key enc_private.pem -out enc_public.pem


Use sign_private.pem and enc_private.pem as EC private keys in callback.(Refer java code)

Hope this helps.
