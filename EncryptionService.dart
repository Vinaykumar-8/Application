import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:cryptography/cryptography.dart';
import 'dart:convert';

class EncryptionService {
  static final X25519 _x25519 = X25519();
  static final AesGcm _aesGcm = AesGcm.with256bits();

  //static const String _privateKeyStorageKey = 'x25519_private_key';
  static const FlutterSecureStorage _storage = const FlutterSecureStorage();

  static Future<String> generateAndStoreIdentityKeyPair(String uid) async {
    final keyPair = await _x25519.newKeyPair();
    final privateKeyBytes = await keyPair.extractPrivateKeyBytes();

    final publicKey = await keyPair.extractPublicKey();

    await _storage.write(
      key:'x25519_private_$uid',
      value:base64Encode(privateKeyBytes),
      );
    return base64Encode(publicKey.bytes);
  }

  static Future<SimpleKeyPairData> loadIdentityPrivateKey(String uid) async{
    final encoded = await _storage.read(
      key:'x25519_private_$uid',
    );
    if(encoded==null){
      throw StateError('X25519 private key not found');
    }
    final privateKeyBytes = base64Decode(encoded);
    final keyPair = await _x25519.newKeyPairFromSeed(privateKeyBytes);

    return await keyPair.extract();
  }

  static Future<SecretKey> derivceSharedSecret(String peerPublicKeyBase64) async {
    final myKeyPair = await loadIdentityPrivateKey();

    final peerPublicKeyBytes = base64Decode(peerPublicKeyBase64);
    final peerPublicKey = SimplePublicKey(peerPublicKeyBytes, type:KeyPairType.x25519);

    return _x25519.sharedSecretKey(keyPair:myKeyPair, peerPublicKey:peerPublicKey);
  }

  static Future<SecretKey> deriveAesKey(SecretKey sharedSecret,) async {
    final hkdf =Hkdf(
      hmac: Hmac.sha256(),
      outputLength: 32,
    );
    return hkdf.deriveKey(
      secretKey: sharedSecret,
      info: utf8.encode('chat-aes-key-v1'),
    );
  }

  static Future<String> encryptMessage(String plainText, SecretKey aesKey) async {
    final nonce = _aesGcm.newNonce();
    final secretBox = await _aesGcm.encrypt(
      utf8.encode(plaintText),
      secretKey: aesKey,
      nonce:nonce,
      );

    return base64Encode(secretBox.concatenation());
  }

  static Future<String> decryptMessage(String encryptedBase64, SecretKey aesKey,) async {
    final secretBox = SecretBox.fromConcatenation(
      base64Decode(encryptedBase64),
      nonceLength: _aesGcm.nonceLength,
      macLength: _aesGcm.macAlgorithm.macLength,
    );

    final clearTextBytes = await _aesGcm.decrypt(
      secretBox,
      secretKey: aesKey,
    );
    return utf8.decode(clearTextBytes);
  }
}
