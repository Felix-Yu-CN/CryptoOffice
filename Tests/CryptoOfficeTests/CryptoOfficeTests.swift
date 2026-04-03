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

@testable import CryptoOffice
import OLEKit
import XCTest
import ZIPFoundation

final class CryptoOfficeTests: XCTestCase {
  private func findEntry(named name: String, in entry: DirectoryEntry) -> DirectoryEntry? {
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

  func testEncryptedStreamsCanBeResolvedFromOLETree() throws {
    let url = URL(fileURLWithPath: #file)
      .deletingLastPathComponent()
      .appendingPathComponent("TestWorkbook.xlsx")

    let oleFile = try OLEFile(url.path)

    let encryptionInfo = try XCTUnwrap(findEntry(named: "EncryptionInfo", in: oleFile.root))
    let encryptedPackage = try XCTUnwrap(findEntry(named: "EncryptedPackage", in: oleFile.root))

    XCTAssertEqual(encryptionInfo.name, "EncryptionInfo")
    XCTAssertEqual(encryptedPackage.name, "EncryptedPackage")
  }

  func testIsEncryptedReturnsTrueForEncryptedFile() throws {
    let url = URL(fileURLWithPath: #file)
      .deletingLastPathComponent()
      .appendingPathComponent("TestWorkbook.xlsx")

    XCTAssertTrue(try CryptoOfficeFile.isEncrypted(path: url.path))
  }

  func testIsEncryptedReturnsFalseForUnencryptedFile() throws {
    XCTAssertFalse(try CryptoOfficeFile.isEncrypted(path: #file))
  }

  func testWorkbook() throws {
    let url = URL(fileURLWithPath: #file)
      .deletingLastPathComponent()
      .appendingPathComponent("TestWorkbook.xlsx")

    let file = try CryptoOfficeFile(path: url.path)
    XCTAssertEqual(
      file.encryptionInfo.keyEncryptors.keyEncryptor[0].encryptedKey.hashAlgorithm,
      "SHA512"
    )

    let data = try file.decrypt(password: "pass")
    guard let archive = Archive(data: data, accessMode: .read)
    else { return XCTFail("archive could not be created from the decrypted file") }

    XCTAssertEqual(Array(archive).count, 10)
  }

  func testDocument() throws {
    let url = URL(fileURLWithPath: #file)
      .deletingLastPathComponent()
      .appendingPathComponent("美国驻华大使 - 加密.docx")

    let file = try CryptoOfficeFile(path: url.path)
    XCTAssertEqual(
      file.encryptionInfo.keyEncryptors.keyEncryptor[0].encryptedKey.hashAlgorithm,
      "SHA1"
    )

    let data = try file.decrypt(password: "123456")
    guard let archive = Archive(data: data, accessMode: .read)
    else { return XCTFail("archive could not be created from the decrypted file") }

    XCTAssertNotNil(archive["[Content_Types].xml"])
    XCTAssertNotNil(archive["word/document.xml"])
  }

  func testDecryptToTemporaryFileWritesDecryptedDocument() throws {
    let url = URL(fileURLWithPath: #file)
      .deletingLastPathComponent()
      .appendingPathComponent("美国驻华大使 - 加密.docx")

    let file = try CryptoOfficeFile(path: url.path)
    let temporaryURL = try file.decryptToTemporaryFile(password: "123456")

    defer { try? FileManager.default.removeItem(at: temporaryURL) }

    XCTAssertEqual(temporaryURL.lastPathComponent, url.lastPathComponent)
    XCTAssertEqual(temporaryURL.deletingLastPathComponent(), FileManager.default.temporaryDirectory)

    let data = try Data(contentsOf: temporaryURL)
    guard let archive = Archive(data: data, accessMode: .read)
    else { return XCTFail("archive could not be created from the temporary decrypted file") }

    XCTAssertNotNil(archive["[Content_Types].xml"])
    XCTAssertNotNil(archive["word/document.xml"])
  }
}
