// Copyright 2020 CoreOffice contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Crypto
import CryptoSwift
import Foundation
import OLEKit

extension Crypto.Digest {
  var data: Data { Data(makeIterator()) }
}

private func littleEndianData<T: FixedWidthInteger>(_ value: T) -> Data {
  var littleEndianValue = value.littleEndian
  return withUnsafeBytes(of: &littleEndianValue) { Data($0) }
}

private enum AgileHashAlgorithm: String, CaseIterable {
  case sha1
  case sha256
  case sha384
  case sha512

  init?(officeName: String?) {
    guard let officeName else { return nil }
    self.init(rawValue: officeName.lowercased())
  }

  func hash(data: Data) -> Data {
    switch self {
    case .sha1:
      return Insecure.SHA1.hash(data: data).data
    case .sha256:
      return SHA256.hash(data: data).data
    case .sha384:
      return SHA384.hash(data: data).data
    case .sha512:
      return SHA512.hash(data: data).data
    }
  }

  static var supportedNames: [String] {
    allCases.map { $0.rawValue }
  }
}

struct AgileInfo: Decodable {
  struct KeyData: Decodable {
    let saltValue: Data
    let hashAlgorithm: String
  }

  struct EncryptedKey: Decodable {
    let spinCount: UInt32
    let encryptedKeyValue: Data
    let encryptedVerifierHashInput: Data
    let encryptedVerifierHashValue: Data
    let saltValue: Data
    let hashAlgorithm: String
    let keyBits: Int
  }

  struct KeyEncryptors: Decodable {
    struct KeyEncryptor: Decodable {
      let encryptedKey: EncryptedKey
    }

    let keyEncryptor: [KeyEncryptor]
  }

  let keyData: KeyData
  let keyEncryptors: KeyEncryptors

  private func deriveKey(from hash: Data, keyBits: Int) -> [UInt8] {
    let keyByteCount = keyBits / 8
    if hash.count >= keyByteCount {
      return Array(hash.prefix(keyByteCount))
    }

    return Array(hash + Data(repeating: 0x00, count: keyByteCount - hash.count))
  }

  private func key(
    for block: Data,
    encryptedKey: EncryptedKey,
    algorithm: AgileHashAlgorithm,
    passwordData: Data
  ) -> [UInt8] {
    var hash = algorithm.hash(data: encryptedKey.saltValue + passwordData)

    for i in 0..<encryptedKey.spinCount {
      let spin = DataWriter()
      spin.write(i)
      hash = algorithm.hash(data: spin.data + hash)
    }

    hash = algorithm.hash(data: hash + block)

    return deriveKey(from: hash, keyBits: encryptedKey.keyBits)
  }

  private func decrypted(
    _ value: Data,
    key: [UInt8],
    iv: Data
  ) throws -> Data {
    let aes = try CryptoSwift.AES(
      key: key,
      blockMode: CBC(iv: Array(iv)),
      padding: .noPadding
    )
    return try Data(aes.decrypt([UInt8](value)))
  }

  func secretKey(password: String) throws -> [UInt8] {
    let encryptedKeyValueBlock = Data([0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6])
    let verifierHashInputBlock = Data([0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79])
    let verifierHashValueBlock = Data([0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E])

    guard let encryptedKey = keyEncryptors.keyEncryptor.first?.encryptedKey else {
      throw CryptoOfficeError.encryptedKeyNotSpecifiedForAgileEncryption
    }

    guard let algorithm = AgileHashAlgorithm(officeName: encryptedKey.hashAlgorithm) else {
      throw CryptoOfficeError.hashAlgorithmNotSupported(
        actual: encryptedKey.hashAlgorithm.lowercased(),
        expected: AgileHashAlgorithm.supportedNames
      )
    }
    guard let passwordData = password.data(using: .utf16LittleEndian)
    else { throw CryptoOfficeError.cantEncodePassword(encoding: .utf16LittleEndian) }

    let verifierInputKey = key(
      for: verifierHashInputBlock,
      encryptedKey: encryptedKey,
      algorithm: algorithm,
      passwordData: passwordData
    )
    let verifierHashKey = key(
      for: verifierHashValueBlock,
      encryptedKey: encryptedKey,
      algorithm: algorithm,
      passwordData: passwordData
    )
    let secretKeyKey = key(
      for: encryptedKeyValueBlock,
      encryptedKey: encryptedKey,
      algorithm: algorithm,
      passwordData: passwordData
    )

    let verifierInput = try decrypted(
      encryptedKey.encryptedVerifierHashInput,
      key: verifierInputKey,
      iv: encryptedKey.saltValue
    )
    let verifierHash = try decrypted(
      encryptedKey.encryptedVerifierHashValue,
      key: verifierHashKey,
      iv: encryptedKey.saltValue
    )
    let expectedHash = algorithm.hash(data: verifierInput)
    guard verifierHash.prefix(expectedHash.count) == expectedHash else {
      throw CryptoOfficeError.passwordVerificationFailed
    }

    return [UInt8](try decrypted(
      encryptedKey.encryptedKeyValue,
      key: secretKeyKey,
      iv: encryptedKey.saltValue
    ))
  }

  func decrypt(
    _ reader: DataReader,
    secretKey: [UInt8],
    processChunk: (Data) throws -> Void,
    progressHandler: ((Double) -> Void)? = nil
  ) throws {
    let segmentLength: UInt32 = 4096

    guard let algorithm = AgileHashAlgorithm(officeName: keyData.hashAlgorithm) else {
      throw CryptoOfficeError.hashAlgorithmNotSupported(
        actual: keyData.hashAlgorithm.lowercased(), expected: AgileHashAlgorithm.supportedNames
      )
    }

    let totalSize: UInt32 = reader.read()
    let lastSegmentSize = totalSize % segmentLength

    reader.seek(toOffset: 8)

    let totalSegments = totalSize / segmentLength + (lastSegmentSize > 0 ? 1 : 0)
    let salt = keyData.saltValue

    for i in 0..<totalSegments {
      let segmentIndexData = littleEndianData(i)
      let ivSource = salt + segmentIndexData
      let iv = Array(algorithm.hash(data: ivSource).prefix(16))
      let aes = try AES(key: secretKey, blockMode: CBC(iv: iv), padding: .noPadding)

      let chunk: Data
      let decryptedChunk: Data
      if i == totalSegments - 1 {
        chunk = reader.readDataToEnd()
        let decryptedData = try Data(aes.decrypt([UInt8](chunk)))
        if lastSegmentSize > 0 {
          decryptedChunk = decryptedData.prefix(Int(lastSegmentSize))
        } else {
          decryptedChunk = decryptedData
        }
      } else {
        chunk = reader.readData(ofLength: Int(segmentLength))
        decryptedChunk = try Data(aes.decrypt([UInt8](chunk)))
        precondition(decryptedChunk.count == 4096)
      }
      try processChunk(decryptedChunk)
      progressHandler?(Double(i + 1) / Double(totalSegments))
    }
  }

  func decrypt(_ reader: DataReader, secretKey: [UInt8]) throws -> Data {
    var result = Data()
    try decrypt(reader, secretKey: secretKey) { chunk in
      result.append(chunk)
    }
    return result
  }
}
