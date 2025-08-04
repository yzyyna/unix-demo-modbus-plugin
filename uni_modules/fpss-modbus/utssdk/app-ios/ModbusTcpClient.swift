import Foundation
import Network
 
public class ModbusTCPClient {
    private var connection: NWConnection?
    
    func connect(host: String, port: UInt16) {
        let host = NWEndpoint.Host(host)
        let port = NWEndpoint.Port(rawValue: port)!
        connection = NWConnection(host: host, port: port, using: .tcp)
        print("Connection object:", connection ?? "nil")

        connection?.stateUpdateHandler = { state in
            switch state {
            case .ready:
                print("Modbus 连接成功")
            case .failed(let error):
                print("连接失败: \(error)")
            default: break
            }
        }
        connection?.start(queue: .main)
    }
    
    func readHoldingRegisters(address: UInt16, count: UInt16, completion: @escaping ([UInt16]?) -> Void) {
        // Modbus TCP 请求报文（事务ID=0, 单元ID=1）
        var request = Data()
        request += [0x00, 0x00] // 事务ID
        request += [0x00, 0x00] // 协议ID (Modbus=0)
        request += [0x00, 0x06] // 长度
        request += [0x01]       // 单元ID
        request += [0x03]       // 功能码（读保持寄存器）
        request += [UInt8(address >> 8), UInt8(address & 0xFF)] // 起始地址
        request += [UInt8(count >> 8), UInt8(count & 0xFF)]     // 寄存器数量
        
        connection?.send(content: request, completion: .idempotent)
        
        connection?.receive(minimumIncompleteLength: 0, maximumLength: 1024) { data, _, _, error in
            guard let data = data, error == nil else {
                completion(nil)
                return
            }
            // 确保数据足够长（至少 9 + 2*count 字节）
             guard data.count  >= 9 + Int(count) * 2 else {
                 completion(nil)
                 return
             }
             
             // 跳过前 9 字节（MBAP 头部）
             let payload = data.dropFirst(9)
             
             // 直接读取 UInt16 数组（大端序）
             let values = payload.withUnsafeBytes  { buffer -> [UInt16] in
                 let words = buffer.bindMemory(to:  UInt16.self)
                 return words.map  { $0.bigEndian  } // 强制大端序
             }
             
             completion(values)
        }
    }
    func writeHoldingRegisters(address: UInt16, values: [UInt16], completion: @escaping (Bool) -> Void) {
        // Modbus TCP 请求报文（事务ID=0, 单元ID=1）
        var request = Data()
        
        // 1. MBAP 头部（事务ID、协议ID、长度、单元ID）
        request += [0x00, 0x00] // 事务ID（可自增）
        request += [0x00, 0x00] // 协议ID (Modbus=0)
        request += [0x00, 0x00] // 长度（稍后填充）
        request += [0x01]       // 单元ID
        
        // 2. 功能码（写多个寄存器）
        request += [0x10]       // 功能码 0x10（写多个寄存器）
        
        // 3. 寄存器地址（大端序）
        request += [UInt8(address >> 8), UInt8(address & 0xFF)]
        
        // 4. 寄存器数量（大端序）
        let registerCount = UInt16(values.count)
        request += [UInt8(registerCount >> 8), UInt8(registerCount & 0xFF)]
        
        // 5. 字节数（每个寄存器占 2 字节）
        request += [UInt8(values.count  * 2)]
        
        // 6. 寄存器值（大端序）
        for value in values {
            request += [UInt8(value >> 8), UInt8(value & 0xFF)]
        }
        
        // 更新长度字段（MBAP 头部的长度 = 后续字节数 + 1）
        let length = UInt16(request.count  - 6) // 从单元ID开始计算
        request[4] = UInt8(length >> 8)
        request[5] = UInt8(length & 0xFF)
        
        // 发送请求
        connection?.send(content: request, completion: .idempotent)
        
        // 接收响应（标准 Modbus TCP 响应长度为 12 字节）
        connection?.receive(minimumIncompleteLength: 0, maximumLength: 12) { data, _, _, error in
            guard let data = data, error == nil else {
                completion(false)
                return
            }
            
            // 验证响应
            // 正确的响应格式：MBAP 头部 + 功能码 + 起始地址 + 寄存器数量
            guard data.count  >= 12,
                  data[7] == 0x10, // 功能码
                  data[8] == request[8], data[9] == request[9], // 地址
                  data[10] == request[10], data[11] == request[11] // 数量
            else {
                completion(false)
                return
            }
            
            completion(true)
        }
    }
}
