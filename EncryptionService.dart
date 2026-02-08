import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:cryptography/cryptography.dart';
import 'dart:convert';

class EncryptionService {
  static final X25519 _x25519 = X25519();
  static final AesGcm _aesGcm = AesGcm.with256bits();

  static const String _privateKeyStorageKey = 'x25519_private_key';
  static const FlutterSecureStorage _storage = const FlutterSecureStorage();

  static Future<String> generateAndStoreIdentityKeyPair() async {
    final keyPair = await _x25519.newKeyPair();
    final privateKeyBytes = await keyPair.extractPrivateKeyBytes();

    final publicKey = await keyPair.extractPublicKey();

    await _storage.write(
      key:_privateKeyStorageKey,
      value:base64Encode(privateKeyBytes),
      );
    return base64Encode(publicKey.bytes);
  }

  static Future<SimpleKeyPairData> loadIdentityPrivateKey() async{
    final encoded = await _storage.read(
      key:_privateKeyStorageKey,
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
    final cipher = OAEPEncoding.withSHA256(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));

    final encrypted = cipher.process(Uint8List.fromList(aesKeyBytes));
    return base64.encode(encrypted);
  }

  static List<int> decryptAESKeyWithRSA(
      String privateKeyPem, String encryptedAesKeyBase64) {
    final privateKey = _parsePrivateKeyFromPem(privateKeyPem);
    final cipher = OAEPEncoding.withSHA256(RSAEngine())
    ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    
    final decrypted = cipher.process(base64.decode(encryptedAesKeyBase64));
    return decrypted;
  }
  static String _encodePublicKeyPKCS8(RSAPublicKey key){
      final algorithmSeq = ASN1Sequence()
        ..add(ASN1ObjectIdentifier.fromName('rsaEncryption'))
        ..add(ASN1Null());

      final publicKeySeq = ASN1Sequence()
        ..add(ASN1Integer(key.modulus!))
        ..add(ASN1Integer(key.exponent!));

      final publicKeyBitString = ASN1BitString()
        ..stringValues = publicKeySeq.encodedBytes!;

      final topLevelSeq = ASN1Sequence()
        ..add(algorithmSeq)
        ..add(publicKeyBitString);

    return _wrapPem('PUBLIC KEY',topLevelSeq.encodedBytes!);
  }
  static String _encodePrivateKeyToPemPKCS8(RSAPrivateKey key){
    final rsaSeq = ASN1Sequence()
      ..add(ASN1Integer(BigInt.zero))
      ..add(ASN1Integer(key.n!))
      ..add(ASN1Integer(key.exponent!))
      ..add(ASN1Integer(key.privateExponent!))
      ..add(ASN1Integer(key.p!))
      ..add(ASN1Integer(key.q!))
      ..add(ASN1Integer(key.privateExponent! % (key.p! - BigInt.one)))
      ..add(ASN1Integer(key.privateExponent! % (key.q! - BigInt.one)))
      ..add(ASN1Integer(key.q!.modInverse(key.p!)));

    final privateKeyOctetString = ASN1OctetString(octets: rsaSeq.encodedBytes);
    final pkcs8 = ASN1Sequence()
      ..add(ASN1Integer(BitInt.zero))
      ..add(ASN1Sequence()
            ..add(ASN1ObjectIndentifier.fromName('rsaEncryption'))
            ..add(ASN1Null()))
      ..add(privateKeyOctetString);
            
    return _wrapPem('PRIVATE KEY', pkcs8.encodedBytes!);
  }
  
  static RSAPublicKey _parsePublicKeyFromPem(String pem){
    final bytes = _decodePem(pem);
    final topLevelSeq = ASN1Parser(bytes).nextObject() as ASN1Sequence;

    final publicKeyBitString = topLevelSeq.elements![1] as ASN1BitString;
    final publicKeyBytes = Uint8List.fromList(publicKeyBitString.stringValues!);
    
    final publicKeySeq = ASN1Parser(publicKeyBytes).nextObject() as ASN1Sequence;
    return RSAPublicKey(
      (publicKeySeq.elements![0] as ASN1Integer).integer!,
      (publicKeySeq.elements![1] as ASN1Integer).integer!,
      );
  }
  static RSAPrivateKey _parsePrivateKeyFromPem(String pem){
    final bytes = _decodePem(pem);
    final topLevel = ASN1Parser(bytes).nextObject() as ASN1Sequence;

    final privateKeyOctet = topLevel.elements![2] as ASN1OctetString;
    final privateKeySeq = ASN1Parser(privateKeyOctet.valueBytes!,).nextObject() as ASN1Sequence;
    
    return RSAPrivateKey(
      (privateKeySeq.elements![1] as ASN1Integer).integer!,
      (privateKeySeq.elements![3] as ASN1Integer).integer!,
      (privateKeySeq.elements![4] as ASN1Integer).integer!,
      (privateKeySeq.elements![5] as ASN1Integer).integer!,
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
