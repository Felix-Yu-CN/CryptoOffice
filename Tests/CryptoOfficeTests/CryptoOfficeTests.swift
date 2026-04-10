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
  private func writeTemporaryOLEHeader(byteOrder: UInt16) throws -> URL {
    let url = FileManager.default.temporaryDirectory
      .appendingPathComponent(UUID().uuidString)
      .appendingPathExtension("ppt")
    var data = Data()

    data.append(contentsOf: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
    data.append(Data(repeating: 0x00, count: 16))

    var minorVersion = UInt16(0x003E).littleEndian
    withUnsafeBytes(of: &minorVersion) { data.append(contentsOf: $0) }

    var dllVersion = UInt16(0x0003).littleEndian
    withUnsafeBytes(of: &dllVersion) { data.append(contentsOf: $0) }

    var byteOrderValue = byteOrder.littleEndian
    withUnsafeBytes(of: &byteOrderValue) { data.append(contentsOf: $0) }

    data.append(Data(repeating: 0x00, count: 512 - data.count))
    try data.write(to: url)
    return url
  }

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

  func testIsEncryptedReturnsFalseForUnsupportedOLEVariant() throws {
    let url = try writeTemporaryOLEHeader(byteOrder: 0xFEFF)
    defer { try? FileManager.default.removeItem(at: url) }

    XCTAssertFalse(try CryptoOfficeFile.isEncrypted(path: url.path))
  }

  func testInitMapsUnsupportedOLEVariantToFileIsNotEncrypted() throws {
    let url = try writeTemporaryOLEHeader(byteOrder: 0xFEFF)
    defer { try? FileManager.default.removeItem(at: url) }

    XCTAssertThrowsError(try CryptoOfficeFile(path: url.path)) { error in
      guard case let CryptoOfficeError.fileIsNotEncrypted(path) = error else {
        return XCTFail("unexpected error: \(error)")
      }

      XCTAssertEqual(path, url.path)
    }
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

  func testDecryptReportsProgress() throws {
    let url = URL(fileURLWithPath: #file)
      .deletingLastPathComponent()
      .appendingPathComponent("美国驻华大使 - 加密.docx")

    let file = try CryptoOfficeFile(path: url.path)
    var progressValues: [Double] = []

    let data = try file.decrypt(password: "123456") { progress in
      progressValues.append(progress)
    }

    XCTAssertFalse(progressValues.isEmpty)
    XCTAssertEqual(try XCTUnwrap(progressValues.last), 1, accuracy: 0.000_001)
    XCTAssertGreaterThan(data.count, 0)
  }

  func testDecryptToTemporaryFileReportsProgress() throws {
    let url = URL(fileURLWithPath: #file)
      .deletingLastPathComponent()
      .appendingPathComponent("美国驻华大使 - 加密.docx")

    let file = try CryptoOfficeFile(path: url.path)
    var progressValues: [Double] = []

    let temporaryURL = try file.decryptToTemporaryFile(password: "123456") { progress in
      progressValues.append(progress)
    }

    defer { try? FileManager.default.removeItem(at: temporaryURL) }

    XCTAssertFalse(progressValues.isEmpty)
    XCTAssertEqual(try XCTUnwrap(progressValues.last), 1, accuracy: 0.000_001)
    XCTAssertTrue(FileManager.default.fileExists(atPath: temporaryURL.path))
  }

  func testDecryptToTemporaryFileRemovesPartialFileOnFailure() throws {
    let url = URL(fileURLWithPath: #file)
      .deletingLastPathComponent()
      .appendingPathComponent("美国驻华大使 - 加密.docx")

    let file = try CryptoOfficeFile(path: url.path)
    let temporaryURL = FileManager.default.temporaryDirectory.appendingPathComponent(url.lastPathComponent)

    try? FileManager.default.removeItem(at: temporaryURL)

    XCTAssertThrowsError(try file.decryptToTemporaryFile(password: "wrong-password")) { error in
      guard case CryptoOfficeError.passwordVerificationFailed = error else {
        return XCTFail("unexpected error: \(error)")
      }
    }

    XCTAssertFalse(FileManager.default.fileExists(atPath: temporaryURL.path))
  }

  func testBenchmarkLargeDocumentDecryption() throws {
    let url = URL(fileURLWithPath: #file)
      .deletingLastPathComponent()
      .appendingPathComponent("城市漫步指南：济州岛，更适合年轻人的短途免签旅行地 - 少数派 - 加密.docx")
    guard FileManager.default.fileExists(atPath: url.path) else {
      throw XCTSkip("large benchmark fixture is not available in this test target layout")
    }
    let iterations = 3

    var decryptTimings: [TimeInterval] = []
    var decryptToFileTimings: [TimeInterval] = []
    var decryptedSize = 0

    for _ in 0..<iterations {
      let file = try CryptoOfficeFile(path: url.path)
      let start = Date()
      let data = try file.decrypt(password: "123456")
      decryptTimings.append(Date().timeIntervalSince(start))
      decryptedSize = data.count
    }

    for _ in 0..<iterations {
      let file = try CryptoOfficeFile(path: url.path)
      let start = Date()
      let temporaryURL = try file.decryptToTemporaryFile(password: "123456")
      decryptToFileTimings.append(Date().timeIntervalSince(start))
      let attributes = try FileManager.default.attributesOfItem(atPath: temporaryURL.path)
      decryptedSize = (attributes[.size] as? NSNumber)?.intValue ?? decryptedSize
      try? FileManager.default.removeItem(at: temporaryURL)
    }

    let decryptAverage = decryptTimings.reduce(0, +) / Double(decryptTimings.count)
    let decryptToFileAverage = decryptToFileTimings.reduce(0, +) / Double(decryptToFileTimings.count)

    print("BENCHMARK large docx size=\(decryptedSize) bytes")
    print("decrypt timings=\(decryptTimings) avg=\(decryptAverage)")
    print("decryptToTemporaryFile timings=\(decryptToFileTimings) avg=\(decryptToFileAverage)")

    XCTAssertGreaterThan(decryptedSize, 0)
  }
}
