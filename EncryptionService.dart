import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'dart:math';
import 'typed_data';
import 'package:pointycastle/export.dart';

class EncryptionService {
  static final _aesAlgorithm = AesGcm.with256bits();
  final _storage = const FlutterSecureStorage();

  static Map<String, String> _generateKeysInBackground(int _) {
    final secureRandom = FortunaRandom();
    final seed = Uint8List(32);
    final random = Random.secure();

    for(int i=0; i<seed.length;i++){
      seed[i] = random.nextInt(256);
    }
    secureRandom.seed(KeyParameter(seed));
    final keyGen = RSAKeyGenerator()
      ..init(ParamtersWithRandom(
        RSAKeyGeneratorParameters(
          BigInt.parse('65537'),
          2048,
          64,
          ),
        secureRandom,
        ),
      );
    final pair = keyGen.generateKeyPair();
    final publicKey = pair.publicKey as RSAPublicKey;
    final privateKey = pair.privateKey as RSAPrivateKey;

    return{
      'public' : _encodePublicKeyToPem(publicKey),
      'private' : _encodePrivateKeyToPem(privateKey),
    };
  }

  static Future<Map<String, String>> generateRSAkeysAsync() async {
    return await compute(_generateKeysInBackground, 0);
  }

  Future<void> savePrivateKey(String privateKey) async {
    await _storage.write(key: 'private_key', value: privateKey);
  }

  Future<String?> getPrivateKey() async {
    return await _storage.read(key :'private_key');
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
    final publicKey = _parsePublicKeyFromPem(receiverPublicKeyPem);
    final cipher = OAEPEncoding(
      RSAEngine(),
      SHA256Digest(),
      SHA256Digest(),
      null,
      )..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));

    final encrypted = cipher.process(Uint8List.fromList(aesKeyBytes));
    return base64.encode(encrypted);
  }

  static List<int> decryptAESKeyWithRSA(
      String privateKeyPem, String encryptedAesKeyBase64) {
    final privateKey = _parsePrivateKeyFromPem(privateKeyPem);
    final cipher = OAEPEncoding(
      RSAEngine(),
      SHA256Digest(),
      SHA256Digest(),
      null,
      )..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    
    final decrypted = cipher.process(base64.decode(encrypted aes key based));
    return decrypted;
  }
  static String _encodePublicKeyToPem(RSAPublicKey key){
      final bytes = ASN1Sequence()
        ..add(ASN1Integer(key.modulus!))
        ..add(ASN1Integer(key.exponent!));
      return _wrapPem('PUBLIC KEY', bytes.encodedBytes);
  }
  static String _encodePrivateKeyToPem(RSAPrivateKey key){
    final seq = ASN1Sequence()
      ..add(ASN1Integer(BigInt.zero))
      ..add(ASN1Integer(key.n!))
      ..add(ASN1Integer(key.exponent!))
      ..add(ASN1Integer(key.privateExponent!))
      ..add(ASN1Integer(key.p!))
      ..add(ASN1Integer(key.q!))
      ..add(ASN1Integer(key.privateExponent! % (key.p! - BigInt.one)))
      ..add(ASN1Integer(key.privateExponent! % (key.q! - BigInt.one)))
      ..add(ASN1Integer(key.q!.modInverse(key.p!)));

    return _wrapPem('PRIVATE KEY', seq.encodedBytes);
  }
  static RSAPublicKey _parsePublicKeyFromPem(String pem){
    final bytes = _decodePem(pem);
    final seq = ASN1Parser(bytes).nextObject() as ASN1Sequence;

    return RSAPublicKey(
      (seq.elements![0] as ASN1Integer).valueAsBigInteger,
      (seq.elements![1] as ASN1Integer).valueAsBigInteger,
      );
  }
  static RSAPrivateKey _parsePrivateKeyFromPem(String pem){
    final bytes = _decodePem(pem);
    final seq = ASN1Parser(bytes).nextObject() as ASN1Sequence;

    return RSAPrivateKey(
      (seq.elements![1] as ASN1Integer).valueAsBigInteger,
      (seq.elements![2] as ASN1Integer).valueAsBigInteger,
      (seq.elements![3] as ASN1Integer).valueAsBigInteger,
      (seq.elements![4] as ASN1Integer).valueAsBigInteger,
      (seq.elements![5] as ASN1Integer).valueAsBigInteger,
      );
  }
  static String _wrapPem(String type, Uint8List data){
    final b64 = base64.encode(data);
    return '-----BEGIN $type-----\n$b64\n-----END $type-----';
  }                                    
  static Uint8List _decodePem(String pem){
    final cleaned = pem
      .replaceAll(RegExp(r'-----.*-----'), '')
      .replaceAll('\n','');

    return base64.decode(cleaned);
  }
}
