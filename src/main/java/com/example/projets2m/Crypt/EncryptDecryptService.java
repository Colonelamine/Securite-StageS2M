package com.example.projets2m.Crypt;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class EncryptDecryptService {
  public static Map<String,Object>mop = new HashMap<>();

    public static void main(String[] args) {
        EncryptDecryptService encryptDecryptService =  new EncryptDecryptService();
        encryptDecryptService.createKeys();
        String val = encryptDecryptService.encryptMessage("heloo word");
        String de = encryptDecryptService.decryptMessage(val);
        System.out.println(val);
        System.out.println(de);
    }
  public  void createKeys(){
      try{
          KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("RSA");
          keyPairGenerator.initialize(4096);
          KeyPair keyPair=keyPairGenerator.generateKeyPair();
          PublicKey publicKey=keyPair.getPublic();
          PrivateKey privateKey= keyPair.getPrivate();
          publicKey.getEncoded();

        /*  byute ==> hex ==>*/
          mop.put("publicKey",publicKey);
          mop.put("privateKey",privateKey);

      } catch (Exception e){
          e.printStackTrace();
      }

  }

  public String encryptMessage (String plainText){
      try {

          Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");
          PublicKey publicKey = (PublicKey) mop.get("publicKey");
          cipher.init(Cipher.ENCRYPT_MODE, publicKey);
          byte[] encrypt = cipher.doFinal(plainText.getBytes());
          return new String(Base64.getEncoder().encodeToString(encrypt));
      }catch (Exception e){
          e.printStackTrace();
      }
      return "error";

      }


    public String decryptMessage (String encryptedMessage){
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");
            PrivateKey privateKey = (PrivateKey) mop.get("privateKey");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypt = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decrypt);
        }catch (Exception e){
            e.printStackTrace();
        }
        return "error";

    }
  }

