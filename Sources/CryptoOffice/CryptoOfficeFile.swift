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

import Foundation
import OLEKit
import XMLCoder

public final class CryptoOfficeFile {
  private let oleFile: OLEFile
  private let sourceURL: URL

  let encryptionInfo: AgileInfo

  let packageEntry: DirectoryEntry

  private static func findEntry(named name: String, in entry: DirectoryEntry) -> DirectoryEntry? {
    if entry.name == name {
      return entry
    }

    for child in entry.children {
      if let match = findEntry(named: name, in: child) {
        return match
      }
    }

    return nil
  }

  public init(path: String) throws {
    do {
      sourceURL = URL(fileURLWithPath: path)
      oleFile = try OLEFile(path)
      guard let infoEntry = Self.findEntry(named: "EncryptionInfo", in: oleFile.root)
      else { throw CryptoOfficeError.fileIsNotEncrypted(path: path) }

      guard let packageEntry = Self.findEntry(named: "EncryptedPackage", in: oleFile.root)
      else { throw CryptoOfficeError.fileIsNotEncrypted(path: path) }

      self.packageEntry = packageEntry
      let stream = try oleFile.stream(infoEntry)

      let major: UInt16 = stream.read()
      let minor: UInt16 = stream.read()
      switch (major, minor) {
      case (4, 4):
        let decoder = XMLDecoder()
        decoder.shouldProcessNamespaces = true

        stream.seek(toOffset: 8)
        let info = try decoder.decode(AgileInfo.self, from: stream.readDataToEnd())
        encryptionInfo = info

      case (2, 2), (3, 2), (4, 2):
        throw CryptoOfficeError.standardEncryptionNotSupported

      case (3, 3), (4, 3):
        throw CryptoOfficeError.extensibleEncryptionNotSupported

      default:
        throw CryptoOfficeError.unknownEncryptionVersion(major: major, minor: minor)
      }
    } catch let OLEError.fileIsNotOLE(path) {
      throw CryptoOfficeError.fileIsNotEncrypted(path: path)
    }
  }

  public static func isEncrypted(path: String) throws -> Bool {
    do {
      let oleFile = try OLEFile(path)
      return
        findEntry(named: "EncryptionInfo", in: oleFile.root) != nil &&
        findEntry(named: "EncryptedPackage", in: oleFile.root) != nil
    } catch OLEError.fileIsNotOLE {
      return false
    }
  }

  public func decrypt(password: String) throws -> Data {
    let secretKey = try encryptionInfo.secretKey(password: password)

    let stream = try oleFile.stream(packageEntry)

    return try encryptionInfo.decrypt(stream, secretKey: secretKey)
  }

  public func decryptToTemporaryFile(password: String) throws -> URL {
    let data = try decrypt(password: password)
    let temporaryDirectory = FileManager.default.temporaryDirectory
    let temporaryURL = temporaryDirectory.appendingPathComponent(sourceURL.lastPathComponent)

    try data.write(to: temporaryURL)
    return temporaryURL
  }
}
