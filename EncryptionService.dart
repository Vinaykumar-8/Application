import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:crypton/crypton.dart' as crypt;
import 'package:flutter/foundation.dart';

class EncryptionService {
  static final _aesAlgorithm = AesGcm.with256bits();
  final _storage = const FlutterSecureStorage();

  static Map<String, String> _generateKeysInBackground(int _) {
    final keypair = crypt.RSAKeypair.fromRandom();
    return {
      'public': keypair.publicKey.toPEM(),
      'private': keypair.privateKey.toPEM(),
    };
  }

  static Future<Map<String, String>> generateRSAkeysAsync() async {
    return await compute(_generateKeysInBackground, 0);
  }

  Future<void> savePrivateKey(String privateKey) async {
    await _storage.write(key: 'private_key', value: privateKey);
  }

  Future<String?> getPrivateKey() async {
    String? raw = await _storage.read(key: 'private_key');
    if (raw == null) {
      return null;
    }
    return raw;
  }

  static Future<String> encryptAES(
      String plainText, List<int> secretKeyBytes) async {
    final secretKey = await _aesAlgorithm.newSecretKeyFromBytes(secretKeyBytes);
    final nonce = _aesAlgorithm.newNonce();
    final secretBox = await _aesAlgorithm.encrypt(
      utf8.encode(plainText),
      secretKey: secretKey,
      nonce: nonce,
    );
    return base64.encode(secretBox.concatenation());
  }

  static Future<String> decryptAES(
      String encryptedData, List<int> secretKeyBytes) async {
    final secretKey = await _aesAlgorithm.newSecretKeyFromBytes(secretKeyBytes);
    final secretBox = SecretBox.fromConcatenation(
      base64.decode(encryptedData),
      nonceLength: _aesAlgorithm.nonceLength,
      macLength: _aesAlgorithm.macAlgorithm.macLength,
    );
    final clearTextBytes = await _aesAlgorithm.decrypt(
      secretBox,
      secretKey: secretKey,
    );
    return utf8.decode(clearTextBytes);
  }

  static String encryptAESKeyWithRSA(
      List<int> aesKeyBytes, String receiverPublicKeyPem) {
    final publicKey = crypt.RSAPublicKey.fromPEM(receiverPublicKeyPem);
    final aesKeyBase64 = base64.encode(aesKeyBytes);

    return publicKey.encrypt(aesKeyBase64);
  }

  static List<int> decryptAESKeyWithRSA(
      String privateKeyPem, String encryptedAesKeyBase64) {
    final privateKey = crypt.RSAPrivateKey.fromPEM(privateKeyPem);
    final decryptedBase64 = privateKey.decrypt(encryptedAesKeyBase64);

    return base64.decode(decryptedBase64);
  }
}
