import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:crypton/crypton.dart';
import 'package:pointycastle/asymmetric/api.dart' as pc;
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';

class EncryptionService {
  static final _aesAlgorithm = AesGcm.with256bits();
  final _storage = const FlutterSecureStorage();

  static Map<String, String> _generateKeysInBackground(int _) {
    final keypair = RSAKeypair.fromRandom();
    return {
      'public': keypair.publicKey.toString(),
      'private': keypair.privateKey.toString(),
    };
  }

  static Future<Map<String, String>> generateRSAkeysAsync() async {
    return await compute(_generateKeysInBackground, 0);
  }

  Future<void> savePrivateKey(String privateKey) async {
    await _storage.write(key: 'private_key', value: privateKey);
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

  Future<String?> getPrivateKey() async {
    String? raw = await _storage.read(key: 'private_key');
    if (raw == null) {
      return null;
    }
    return utf8.decode(base64.decode(raw));
  }

  static String encryptMessage(
      String plainText, String receiverPublicKeyString) {
    try {
      final publicKey = RSAPublicKey.fromString(receiverPublicKeyString);
      return publicKey.encrypt(plainText);
    } catch (e) {
      print("RSA Encrypt Error: $e");
      return "";
    }
  }

  static String decryptMessage(String cipherText, String myPrivateKeyString) {
    try {
      final base64Regex = RegExp(r'[a-zA-Z0-9+/=]+');
      final matches = base64Regex.allMatches(myPrivateKeyString);
      String cleanBase64 = matches.map((m) => m.group(0)).join('');

      final String header = "-----BEGIN\x20PRIVATE\x20KEY-----";
      final String footer = "-----END\x20PRIVATE\x20KEY-----";

      final String formattedKey = "$header\n$cleanBase64\n$footer";
      print("Formatted Key with headers is: $formattedKey");

      final privateKey = RSAPrivateKey.fromString(formattedKey);
      return privateKey.decrypt(cipherText);
    } catch (e) {
      print("Crypton Decrypt Error: $e");
      print("Key starts with: ${myPrivateKeyString.substring(0, 20)}");
      throw Exception("Failed to decrypt RSA: $e");
    }
  }
}
