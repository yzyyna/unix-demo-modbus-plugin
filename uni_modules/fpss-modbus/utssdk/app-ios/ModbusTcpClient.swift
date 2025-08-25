import Foundation
import Network

public class ModbusTCPClient {
    public enum ProtocolMode {
        case tcp
        case rtuOverTcp
    }

    private var connection: NWConnection?
    private let mode: ProtocolMode

    public init(mode: ProtocolMode) {
        self.mode = mode
    }

    public func connect(
        host: String,
        port: UInt16,
        onStateChange: @escaping (String) -> Void
    ) {
        let host = NWEndpoint.Host(host)
        let port = NWEndpoint.Port(rawValue: port)!
        connection = NWConnection(host: host, port: port, using: .tcp)

        connection?.stateUpdateHandler = { state in
            switch state {
            case .ready:     onStateChange("ready")
            case .failed(_): onStateChange("failed")
            case .waiting(_):onStateChange("waiting")
            case .cancelled: onStateChange("cancelled")
            case .preparing: onStateChange("preparing")
            default:         onStateChange("unknown")
            }
        }
        connection?.start(queue: .main)
    }

    // MARK: - 公共寄存器读取
    public func readHoldingRegisters(
        unitId: UInt8 = 1,
        address: UInt16,
        count: UInt16,
        completion: @escaping ([UInt16]?) -> Void
    ) {
        let request = buildReadRequest(unitId: unitId, address: address, count: count)

        connection?.send(content: request, completion: .idempotent)

        // 最大长度 = TCP模式 9+count*2 / RTU模式 3+count*2+2
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 256) { data, _, _, error in
            guard let data = data, error == nil else {
                completion(nil)
                return
            }
            self.parseResponse(data, mode: self.mode, completion: completion)
        }
    }

    // MARK: - 公共寄存器写入
    public func writeHoldingRegisters(
        unitId: UInt8 = 1,
        address: UInt16,
        values: [UInt16],
        completion: @escaping (Bool) -> Void
    ) {
        let request = buildWriteRequest(unitId: unitId, address: address, values: values)

        connection?.send(content: request, completion: .idempotent)

        connection?.receive(minimumIncompleteLength: 1, maximumLength: 256) { data, _, _, error in
            guard let data = data, error == nil else {
                completion(false)
                return
            }

            switch self.mode {
            case .tcp:
                completion(data.count >= 12 && data[7] == 0x10)
            case .rtuOverTcp:
                let bytes = [UInt8](data)
                guard bytes.count >= 8 else { completion(false); return }
                let recvCrc = UInt16(bytes[bytes.count - 2]) | (UInt16(bytes.last!) << 8)
                let calcCrc = modbusCRC16(Array(bytes.dropLast(2)))
                completion(recvCrc == calcCrc)
            }
        }
    }

    // MARK: - 请求构造
    private func buildReadRequest(unitId: UInt8, address: UInt16, count: UInt16) -> Data {
        switch mode {
        case .tcp:
            var req = Data()
            req.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
            req.append(contentsOf: [0x00, 0x06])
            req.append(unitId)
            req.append(0x03)
            req.append(UInt8(address >> 8))
            req.append(UInt8(address & 0xFF))
            req.append(UInt8(count >> 8))
            req.append(UInt8(count & 0xFF))
            return req
        case .rtuOverTcp:
            var req = Data()
            req.append(unitId)
            req.append(0x03)
            req.append(UInt8(address >> 8))
            req.append(UInt8(address & 0xFF))
            req.append(UInt8(count >> 8))
            req.append(UInt8(count & 0xFF))
            let crc = modbusCRC16(Array(req))
            req.append(UInt8(crc & 0xFF))
            req.append(UInt8(crc >> 8))
            return req
        }
    }

    private func buildWriteRequest(unitId: UInt8, address: UInt16, values: [UInt16]) -> Data {
        switch mode {
        case .tcp:
            var req = Data()
            req.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
            req.append(contentsOf: [0x00, 0x00]) // 长度占位
            req.append(unitId)
            req.append(0x10)
            req.append(UInt8(address >> 8))
            req.append(UInt8(address & 0xFF))
            let regCount = UInt16(values.count)
            req.append(UInt8(regCount >> 8))
            req.append(UInt8(regCount & 0xFF))
            req.append(UInt8(values.count * 2))
            for v in values {
                req.append(UInt8(v >> 8))
                req.append(UInt8(v & 0xFF))
            }
            let length = UInt16(req.count - 6)
            req[4] = UInt8(length >> 8)
            req[5] = UInt8(length & 0xFF)
            return req
        case .rtuOverTcp:
            var req = Data()
            req.append(unitId)
            req.append(0x10)
            req.append(UInt8(address >> 8))
            req.append(UInt8(address & 0xFF))
            let regCount = UInt16(values.count)
            req.append(UInt8(regCount >> 8))
            req.append(UInt8(regCount & 0xFF))
            req.append(UInt8(values.count * 2))
            for v in values {
                req.append(UInt8(v >> 8))
                req.append(UInt8(v & 0xFF))
            }
            let crc = modbusCRC16(Array(req))
            req.append(UInt8(crc & 0xFF))
            req.append(UInt8(crc >> 8))
            return req
        }
    }

    // MARK: - 安全解析
    // MARK: - 安全解析
    private func parseResponse(_ data: Data, mode: ProtocolMode, completion: ([UInt16]?) -> Void) {
        let bytes = [UInt8](data)

        switch mode {
        case .tcp:
            guard bytes.count >= 9 else { completion(nil); return }
            let byteCount = Int(bytes[8])
            let dataStart = 9
            let dataEnd = dataStart + byteCount
            guard bytes.count >= dataEnd else { completion(nil); return }
            let dataBytes = bytes[dataStart..<dataEnd]
            // 新增：偶数长度校验
            guard dataBytes.count % 2 == 0 else {
                print("数据区字节数异常: \(dataBytes.count)")
                completion(nil); return
            }
            completion(parseRegisters(from: dataBytes))

        case .rtuOverTcp:
            guard bytes.count >= 5 else { completion(nil); return }

            let recvCrc = UInt16(bytes[bytes.count - 2]) | (UInt16(bytes.last!) << 8)
            let calcCrc = modbusCRC16(Array(bytes.dropLast(2)))
            guard recvCrc == calcCrc else {
                print("CRC 校验失败")
                completion(nil)
                return
            }

            if bytes[1] & 0x80 != 0 {
                print("收到异常响应, 异常码: \(bytes[2])")
                completion(nil)
                return
            }

            let byteCount = Int(bytes[2])
            let dataStart = 3
            let dataEnd = dataStart + byteCount
            guard bytes.count >= dataEnd + 2 else { completion(nil); return }
            let dataBytes = bytes[dataStart..<dataEnd]
            // 新增：偶数长度校验
            guard dataBytes.count % 2 == 0 else {
                print("数据区字节数异常: \(dataBytes.count)")
                completion(nil); return
            }
            completion(parseRegisters(from: dataBytes))
        }
    }

    private func parseRegisters(from dataBytes: ArraySlice<UInt8>) -> [UInt16] {
        // 转成 Array，保证下标从 0 开始
        let arr = Array(dataBytes)
        var values: [UInt16] = []

        for i in stride(from: 0, to: arr.count, by: 2) {
            guard i + 1 < arr.count else { break }
            let hi = UInt16(arr[i])
            let lo = UInt16(arr[i + 1])
            values.append((hi << 8) | lo)
        }

        print("解析寄存器值: \(values)")
        return values
    }

}

// MARK: - CRC16 计算
func modbusCRC16(_ bytes: [UInt8]) -> UInt16 {
    var crc: UInt16 = 0xFFFF
    for b in bytes {
        crc ^= UInt16(b)
        for _ in 0..<8 {
            if crc & 0x0001 != 0 {
                crc >>= 1
                crc ^= 0xA001
            } else {
                crc >>= 1
            }
        }
    }
    return crc
}
