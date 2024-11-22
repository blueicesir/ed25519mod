package ed25519mod

import (
    "crypto/ed25519"
    "encoding/pem"
    "fmt"
    "golang.org/x/crypto/ssh"
)

// 返回加密的私钥以及公钥
func Make_Ed25519_KeyPair(encrypt_password string,comment string) (string,string,error) {
    pubKey, privKey, err := ed25519.GenerateKey(nil) // nil will use crypto/rand.Reader
    if err != nil {
        return "","",fmt.Errorf("Make_Ed25519_KeyPair::gen key pair fail,%v", err)
    }

    publicKey,err := ssh.NewPublicKey(pubKey)
    if err != nil {
        return "","",fmt.Errorf("Make_Ed25519_KeyPair::ed25519 public key to ssh public key,%v", err)
    }
    pubKeyString := string(ssh.MarshalAuthorizedKey(publicKey))
    encryptedPEM, err := ssh.MarshalPrivateKeyWithPassphrase(privKey, comment, []byte(encrypt_password))
    if err != nil {
        return "","",fmt.Errorf("EncryptKey::encrypt with private fail,%v", err)
    }
    encryptedPEMBytes := pem.EncodeToMemory(encryptedPEM)
    return string(encryptedPEMBytes),pubKeyString,nil
}

/*
// Example:
func main() {
    private_pem,ssh_pub_key,err:=Make_Ed25519_KeyPair("Cipher_Password","comment note")
    if err!=nil{
        fmt.Printf("Make_Ed25519_KeyPair fail,%v\n",err)
    }else{
        fmt.Println(private_pem)
        fmt.Println(ssh_pub_key)
    }
}
*/
