// syn_scan.go - SYN scanning tool
// This tool detects whether target IPs and ports are open by sending SYN packets and listening for SYN+ACK responses
// Supports single IPs and CIDR format IP ranges, with rate limiting and concurrent control
package main

import (
    "bytes"
    "context"
    "errors"
    "flag"
    "fmt"
    "hash/fnv"
    "log"
    "math/rand"
    "net"
    "os"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "time"
    "unsafe"

    "github.com/google/gopacket"      // for handling network packets
    "github.com/google/gopacket/layers" // provides network protocol layer definitions
    "github.com/google/gopacket/pcap"   // provides network packet capture functionality
    "golang.org/x/time/rate" // for limiting send rate
    netroute "github.com/libp2p/go-netroute" // for getting routing information
)

// Global variables
var send_finish chan bool // channel for send completion signal
var sync_map sync.Map     // for storing discovered open ports, preventing duplicate records

// BASE_INFO structure contains basic information required for scanning
type BASE_INFO struct {
    Iface          *net.Interface   // network interface
    SrcMac, DstMac net.HardwareAddr // source MAC address and destination MAC address
    SrcIp, GateWay net.IP           // source IP address and gateway IP address
    PcapHandle     *pcap.Handle     // pcap handle for sending and receiving packets
    MurmurSeed     uint32           // for generating sequence numbers, facilitating response packet verification
    HashFnv        sync.Map         // for removing duplicate IP:Port combinations in response packets
    Ratelimit      *rate.Limiter    // for limiting send rate
}

// Parse_all2single_ip parses input IP string into a list of individual IP addresses
// Input format example: "22.35.45.76,34.54.44.0/24" => returns a list of all individual IPs
func Parse_all2single_ip(input_ip string) ([]string, error) {
    var output_string []string
    
    // Split input string by comma
    s_tmp := strings.Split(input_ip, ",")
    
    // Process each IP or CIDR
    for i, kv := range s_tmp {
        // If contains '/', treat as CIDR
        if strings.Contains(kv, "/") {
            tmp_ip_list, err := ParseCidr(kv)
            if err != nil {
                log.Fatalf("%d  %s parser error:%v", i, kv, err) // Exit directly on parsing error
            }
            output_string = String_list_append(output_string, tmp_ip_list)
        } else {
            // Treat as single IP
            single_ip := net.ParseIP(kv)
            if single_ip == nil {
                log.Fatalf("%s parse error", kv)
            }
            output_string = append(output_string, kv)
        }
    }

    // Check if valid IPs are found
    if len(output_string) >= 1 {
        return output_string, nil
    } else {
        return []string{}, errors.New("no valid ip found")
    }
}
// String_list_append merges multiple string lists into one list
func String_list_append(nums ...[]string) (result_string_list []string) {
    // Pre-allocate sufficient space to improve performance
    total := 0
    for _, list := range nums {
        total += len(list)
    }
    result_string_list = make([]string, 0, total)
    
    // Merge all lists
    for _, kv := range nums {
        for _, kvj := range kv {
            result_string_list = append(result_string_list, kvj)
        }
    }
    return result_string_list
}
// ParseCidr parses CIDR format IP range and returns all individual IP addresses within the range
func ParseCidr(cidr string) ([]string, error) {
    // Parse CIDR format
    ip, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return nil, err
    }

    // Calculate the number of addresses in the IP range (rough estimate)
    mask_ones, mask_bits := ipnet.Mask.Size()
    size := 1 << uint(mask_bits-mask_ones)
    
    // Pre-allocate sufficient space
    ips := make([]string, 0, size)
    
    // Iterate through all addresses in the IP range
    for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
        ips = append(ips, ip.String())
    }
    
    // Remove network address and broadcast address
    if len(ips) > 2 {
        return ips[1 : len(ips)-1], nil
    }
    return ips, nil
    // Note: IP addresses ending with 0 and 255 cannot be used for IP allocation as they are broadcast addresses
    // They cannot be used on regular computers, but can be used on gateways and routers
}
// inc increments IP address by 1
func inc(ip net.IP) {
    // Start incrementing from the lowest byte
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        // If current byte doesn't overflow (not equal to 0), stop incrementing
        if ip[j] > 0 {
            break
        }
        // If equals 0, overflow occurred, continue incrementing the previous byte
    }
}

// Array_shuffle randomly shuffles elements in string slice
// Returns a new slice without modifying the original slice
func Array_shuffle(array_list []string) []string {
    // If input slice is empty, return empty slice directly
    if len(array_list) == 0 {
        return []string{}
    }
    
    // Create a copy of the original slice to avoid modifying original data
    result := make([]string, len(array_list))
    copy(result, array_list)

    // Create independent random source using current time as seed
    source := rand.NewSource(time.Now().UnixNano())
    r := rand.New(source)

    // Perform shuffle using independent random source
    r.Shuffle(len(result), func(i, j int) {
        result[i], result[j] = result[j], result[i]
    })

    return result
}

// get_eth_info gets network interface information including MAC addresses, gateway, etc.
// Parameters:
//   - dst_ip: target IP address
// Returns:
//   - iface: network interface
//   - src_mac: source MAC address
//   - dst_mac: destination MAC address (usually gateway's MAC address)
//   - src: source IP address
//   - gw: gateway IP address
func get_eth_info(dst_ip string) (iface *net.Interface, src_mac net.HardwareAddr, dst_mac net.HardwareAddr, src net.IP, gw net.IP) {
    ip := net.ParseIP(dst_ip)
    if ip == nil {
        log.Fatal("ip is invalid")
    }
    fmt.Println("get_eth_info ip:", ip)

    r, err := netroute.New()
    if err != nil {
        log.Fatal("netroute err:", err)
    }
    iface, gw, src, err = r.Route(ip)
    log.Printf("iface:%v\tgw:%v\tsrc:%v", iface, gw, src)

    // There are cases where IP is obtained correctly but interface name is wrong, so add correction
    interfaces, err := net.Interfaces()
    if err != nil {
        log.Fatal("GET IFACES ERR:", err)
    }
    for _, ifs := range interfaces {
        byname, err := net.InterfaceByName(ifs.Name)
        if err != nil {
            log.Fatal("get ifsbyname err :", err)
        }
        addresses, err := byname.Addrs()
        for _, addr := range addresses {
            if strings.Split(addr.String(), "/")[0] == src.String() { // addr.String() => 103.99.179.29/24
                // log.Println("addr == src", addr.String(), ifs)
                if ifs.Name != iface.Name {
                    iface.Name = ifs.Name
                }
            } /*else{
                log.Println("addr !== src", addr.String(), ifs)
            }*/
        }
    }

    log.Printf("222 iface:%v\tgw:%v\tsrc:%v\tiface_name:%#v\n", iface, gw, src, iface.Name)
    // Note: on Windows, the interface name obtained here may not match the actual interface name, so correction is needed
    // Reference link: https://haydz.github.io/2020/07/06/Go-Windows-NIC.html
    if runtime.GOOS == "windows" {
        // Find all devices
        devices, err := pcap.FindAllDevs()
        if err != nil {
            log.Fatal(err)
        }

        // Print device information
        // fmt.Println(devices)
        fmt.Println("Devices found:")
        for _, device := range devices {
            fmt.Println("\nName: ", device.Name)
            fmt.Println("Desc: ", device.Description)
            fmt.Println("flags: ", device.Flags)
            fmt.Println("Address: ", device.Addresses)
            for _, addr := range device.Addresses {
                if addr.IP.String() == src.String() { //
                    iface.Name = device.Name
                }
            }
        }

    }

    handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
    if err != nil {
        log.Fatalf("openlive error:%#v\n", err)
    }
    defer handle.Close()

    start := time.Now()
    arpDst := ip
    if gw != nil {
        log.Println("gw is not nil", gw)
        arpDst = gw
    }
    eth := layers.Ethernet{
        SrcMAC:       iface.HardwareAddr,
        DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
        EthernetType: layers.EthernetTypeARP,
    }
    arp := layers.ARP{
        AddrType:          layers.LinkTypeEthernet,
        Protocol:          layers.EthernetTypeIPv4,
        HwAddressSize:     6,
        ProtAddressSize:   4,
        Operation:         layers.ARPRequest,
        SourceHwAddress:   []byte(iface.HardwareAddr),
        SourceProtAddress: []byte(src),
        DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
        DstProtAddress:    []byte(arpDst),
    }
    opts := gopacket.SerializeOptions{
        FixLengths:       true,
        ComputeChecksums: true,
    }
    buf := gopacket.NewSerializeBuffer()
    err = gopacket.SerializeLayers(buf, opts, &eth, &arp)
    if err != nil {
        log.Fatal(err) //nil, err
    }
    log.Println("handle write data")
    handle.WritePacketData(buf.Bytes())

    // Wait 3 seconds for an ARP reply.
    for {
        if time.Since(start) > time.Second*10 {
            log.Println("10 seconds timeout")
            break 
        }
        data, _, err := handle.ReadPacketData()
        if err == pcap.NextErrorTimeoutExpired {
            log.Println("NextErrorTimeoutExpired")
            break 
        } else if err != nil {
            log.Println(err)
            break 
        }
        packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
        if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
            arp := arpLayer.(*layers.ARP)
            if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDst)) {
                log.Println("dst mac is : ", net.HardwareAddr(arp.SourceHwAddress))
                dst_mac = net.HardwareAddr(arp.SourceHwAddress)
                break
            }
            log.Println("SourceProtAddress is not equal")
        }
    }

    return iface, iface.HardwareAddr, dst_mac, src, gw
}

// send_serializelayer serializes and sends network packets
// Parameters:
//   - baseinfo: basic information structure
//   - eth: Ethernet layer
//   - ip4: IPv4 layer
//   - tcp: TCP layer
//   - buffer: serialization buffer
//   - options: serialization options
// Returns:
//   - err: error information
func send_serializelayer(baseinfo *BASE_INFO, eth layers.Ethernet, ip4 layers.IPv4, tcp layers.TCP, buffer gopacket.SerializeBuffer, options gopacket.SerializeOptions) (err error) {
    err = gopacket.SerializeLayers(buffer, options, &eth, &ip4, &tcp)
    if err != nil {
        //log.Fatal("gopacket.SerializeLayers  err",err)
        return err
    }

    err = baseinfo.PcapHandle.WritePacketData(buffer.Bytes()) //handle.WritePacketData(buffer.Bytes())
    if err != nil {
        //log.Println("handle.WritePacketData err:",err)
        return err
    }

    return nil
}
// ip_port_send sends SYN packets to specified ports of target IP list
// Parameters:
//   - baseinfo: basic information structure
//   - dst_ip_list: target IP address list
//   - dst_port: target port
func ip_port_send(baseinfo *BASE_INFO, dst_ip_list []string, dst_port string) {
    send_time := time.Now()
    c, cancel := context.WithCancel(context.Background())
    defer cancel() // Ensure context is cancelled
    
    // Create wait group to ensure all goroutines complete
    var wg sync.WaitGroup
    
    // Limit the number of concurrent goroutines
    maxConcurrent := 100
    semaphore := make(chan struct{}, maxConcurrent)
    
    for _, kv_ip := range dst_ip_list {
        // Wait for rate limiter to allow sending
        baseinfo.Ratelimit.Wait(c)
        
        // Acquire semaphore
        semaphore <- struct{}{}
        wg.Add(1)
        
        go func(kv_ip string, dst_port string) {
            defer wg.Done()
            defer func() { <-semaphore }() // Release semaphore
            
            // Build IP:Port string and calculate sequence number
            var b_send bytes.Buffer
            b_send.WriteString(kv_ip + ":" + dst_port)
            send_seq := Murmur3_Sum32WithSeed(b_send.Bytes(), baseinfo.MurmurSeed)
            
            // Parse target port
            port2, err := strconv.ParseUint(dst_port, 10, 16)
            if err != nil {
                log.Printf("Port parsing error %s: %v", dst_port, err)
                return
            }
            
            // Build Ethernet layer
            eth := layers.Ethernet{
                SrcMAC:       baseinfo.SrcMac,
                DstMAC:       baseinfo.DstMac,
                EthernetType: layers.EthernetTypeIPv4,
            }
            
            // Build IP layer
            ip4 := layers.IPv4{
                SrcIP:    baseinfo.SrcIp,
                DstIP:    net.ParseIP(kv_ip),
                Version:  0x04,
                TTL:      0xff,
                IHL:      0x05, // Internet Header Length
                TOS:      0,
                Protocol: layers.IPProtocolTCP,
            }
            
            // Build TCP layer
            tcp := layers.TCP{
                SrcPort: 12345,
                DstPort: layers.TCPPort(uint16(port2)),
                SYN:     true,
                Seq:     send_seq,
            }
            tcp.SetNetworkLayerForChecksum(&ip4)

            // Serialize and send packet
            buffer := gopacket.NewSerializeBuffer()
            options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
            err = send_serializelayer(baseinfo, eth, ip4, tcp, buffer, options)
            if err != nil {
                log.Printf("Send packet error %s:%s: %v", kv_ip, dst_port, err)
            }

        }(kv_ip, dst_port)
    }
    
    // Wait for all sending goroutines to complete
    go func() {
        wg.Wait()
        send_stop_time := time.Now()
        log.Println("Send completed, elapsed time:", send_stop_time.Sub(send_time))
        log.Println("Waiting 10 seconds cooldown time, then receive function will exit")
        time.Sleep(time.Second * 10)
        send_finish <- true
    }()
}
// ip_port_recv receives and processes SYN+ACK response packets
// Parameters:
//   - baseinfo: basic information structure
//   - file_w: result output file
func ip_port_recv(baseinfo *BASE_INFO, file_w *os.File) {
    //send_src_ip := baseinfo.SrcIp.String()
    for {
        select {
        case <-send_finish:
            log.Println("send finish,recv will finish yet")
            file_w.Sync() // Sync cache, write to file
            return
        default:
            data /*captureinfo*/, _, err := baseinfo.PcapHandle.ReadPacketData() //handle.ReadPacketData()
            if err != nil {
                //log.Println("handle.ReadPacketData  err",err)
                continue
            }
            //log.Printf("data:%v \n captureinfo:%v",data,captureinfo)

            // Parse the packet.  We'd use DecodingLayerParser here if we
            // wanted to be really fast.
            var eth_recv layers.Ethernet
            var ip4_recv layers.IPv4
            //var ip6 layers.IPv6
            var tcp_recv layers.TCP
            parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth_recv, &ip4_recv, &tcp_recv)
            decoded := []gopacket.LayerType{}
            if err := parser.DecodeLayers(data, &decoded); err != nil {
                //log.Println("Could not decode layers: %v\n", err)
                continue
            }
            for _, layerType := range decoded {
                switch layerType {
                case layers.LayerTypeIPv4:
                    //fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
                    if bytes.Compare(ip4_recv.DstIP, baseinfo.SrcIp) != 0 /*baseinfo.SrcIp.String()==send_src_ip*/ {
                        break
                    }
                case layers.LayerTypeTCP:
                    //fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
                    if tcp_recv.DstPort != 12345 {
                        break
                    }

                    if tcp_recv.SYN && tcp_recv.ACK {
                        go recv_syn_ack(baseinfo, file_w, ip4_recv, tcp_recv)
                    }
                }
            }

        }

    }
}
// recv_syn_ack 处理接收到的SYN+ACK包
// 参数:
//   - baseinfo: 基本信息结构体
//   - file_w: 结果输出文件
//   - ip4_recv: 接收到的IPv4层
//   - tcp_recv: 接收到的TCP层
func recv_syn_ack(baseinfo *BASE_INFO, file_w *os.File, ip4_recv layers.IPv4, tcp_recv layers.TCP) {
    var b_recv bytes.Buffer
    b_recv.WriteString(ip4_recv.SrcIP.String() + ":" + strconv.Itoa(int(tcp_recv.SrcPort)))
    recv_validate_seq_ack := Murmur3_Sum32WithSeed(b_recv.Bytes(), baseinfo.MurmurSeed)
    if recv_validate_seq_ack == tcp_recv.Ack-1 {
        ip_str := ip4_recv.SrcIP.String()
        port_str := strconv.Itoa(int(tcp_recv.SrcPort))
        hash_uint32 := Hash_fnv(ip_str + ":" + port_str)
        // Use sync.Map to prevent concurrent map read and map write
        /*value*/
        _, ok := baseinfo.HashFnv.Load(hash_uint32) ///*value*/_,ok := baseinfo.HashFnv[hash_uint32]
        if ok {                                     // This ip:port already exists, skip
            return //continue
        }
        baseinfo.HashFnv.Store(hash_uint32, 1) //baseinfo.HashFnv[hash_uint32] = 1 // This ip:port record doesn't exist, record it for deduplication
        file_w.WriteString(ip_str + "," + port_str + "\n")
    }
}
// syn_scan executes SYN scanning
// Parameters:
//   - baseinfo: basic information structure
//   - ip_list: target IP address list
//   - dst_port: target port
func syn_scan(baseinfo *BASE_INFO, ip_list []string, dst_port string) {
    // Create result file
    time_now := time.Now().Format("2006-01-02-15-04-05")
    filename := "scan_result_" + time_now + ".csv"
    file_w, err := os.Create(filename)
    if err != nil {
        log.Fatalf("Failed to create result file: %v", err)
    }
    defer file_w.Close()
    
    // Write CSV file header
    _, err = file_w.WriteString("IP Address,Port\n")
    if err != nil {
        log.Printf("Failed to write file header: %v", err)
    }

    // Create send completion signal channel
    send_finish = make(chan bool, 1) // Use buffered channel to prevent blocking
    
    // Start receiving goroutine
    log.Println("Starting receive processing...")
    go ip_port_recv(baseinfo, file_w)
    
    // Wait for receive processing to be ready
    time.Sleep(time.Second * 1)
    
    // Start send processing
    log.Printf("Starting to send SYN packets to %d targets...", len(ip_list))
    ip_port_send(baseinfo, ip_list, dst_port)
    
    log.Printf("Scan results will be saved to: %s", filename)
}

//======================<<<<<<<<<<<<  send  and recv SYN packet <<<<<<<<<<<<<<<

// main function, program entry point
func main() {
    start := time.Now()

    // Print libpcap version information
    version := pcap.Version()
    log.Println("Using libpcap version:", version)

    // Define command line parameters
    var dst_ip string
    var dst_port string
    var step_rate int
    flag.StringVar(&dst_ip, "ip", "", "Target IP address, supports single IP or CIDR format: e.g., 172.168.1.2,21.32.34.2/24")
    flag.StringVar(&dst_port, "port", "", "Target port")
    flag.IntVar(&step_rate, "rate", 100, "Packet sending concurrency rate")
    flag.Parse()
    
    // Validate required parameters
    if dst_ip == "" {
        flag.PrintDefaults()
        log.Fatal("\nTarget IP address must be specified")
    }
    if dst_port == "" {
        flag.PrintDefaults()
        log.Fatal("\nTarget port must be specified")
    }
    
    // Parse IP addresses
    ip_list, err := Parse_all2single_ip(dst_ip)
    if err != nil {
        log.Fatal("Failed to parse IP addresses:", err)
    }
    log.Printf("Parsed %d target IP addresses", len(ip_list))
    
    // Randomly shuffle IP list to prevent firewall detection of patterns
    shuffle_ip_list := Array_shuffle(ip_list)

    // Get network interface information
    iface, src_mac, dst_mac, src_ip, gw := get_eth_info(shuffle_ip_list[0]) // Use first IP to get network info
    log.Printf("\nNetwork interface: %v\nSource MAC: %v\nDestination MAC: %v\nSource IP: %v\nGateway: %v\n", 
        iface.Name, src_mac, dst_mac, src_ip, gw)

    // Open network interface for packet capture
    handle, err := pcap.OpenLive(iface.Name, 65535, false, time.Second*3) // Do not enable promiscuous mode
    if err != nil {
        log.Fatalf("Failed to open network interface: %s", iface.Name)
    }
    defer handle.Close()

    // Create random seed and rate limiter
    seed := rand.Uint32()
    var limiter = rate.NewLimiter(rate.Limit(step_rate), 5) // Token bucket capacity is 5
    
    // Initialize basic information structure
    baseinfo := &BASE_INFO{
        Iface:      iface,
        SrcMac:     src_mac,
        DstMac:     dst_mac,
        SrcIp:      src_ip,
        GateWay:    gw,
        PcapHandle: handle,
        MurmurSeed: seed,
        HashFnv:    sync_map,
        Ratelimit:  limiter,
    }

    // Execute SYN scan
    log.Printf("Starting to scan port %s on %d IP addresses", dst_port, len(shuffle_ip_list))
    syn_scan(baseinfo, shuffle_ip_list, dst_port)

    // Statistics
    stop := time.Now()
    num_results := 0
    baseinfo.HashFnv.Range(func(_, _ interface{}) bool {
        num_results += 1
        return true
    })
    log.Printf("Scan completed, time elapsed: %v\tFound %d open ports", stop.Sub(start), num_results)
}

// =====================>>>>>>>>>>>>>> Murmur32 hash algorithm (for generating sequence numbers) <<<<<<<<<<<<<<<<===================
const (
    c1_32 uint32 = 0xcc9e2d51
    c2_32 uint32 = 0x1b873593
)
// Murmur3_Sum32WithSeed calculates MurmurHash3 hash value of data
// Parameters:
//   - data: data to calculate hash
//   - seed: hash seed
// Returns:
//   - 32-bit hash value
// This function is equivalent to the following operations (but avoids additional memory allocation):
//   hasher := New32WithSeed(seed)
//   hasher.Write(data)
//   return hasher.Sum32()
func Murmur3_Sum32WithSeed(data []byte, seed uint32) uint32 {

    h1 := seed

    nblocks := len(data) / 4
    var p uintptr
    if len(data) > 0 {
        p = uintptr(unsafe.Pointer(&data[0]))
    }
    p1 := p + uintptr(4*nblocks)
    for ; p < p1; p += 4 {
        k1 := *(*uint32)(unsafe.Pointer(p))

        k1 *= c1_32
        k1 = (k1 << 15) | (k1 >> 17) // rotl32(k1, 15)
        k1 *= c2_32

        h1 ^= k1
        h1 = (h1 << 13) | (h1 >> 19) // rotl32(h1, 13)
        h1 = h1*4 + h1 + 0xe6546b64
    }

    tail := data[nblocks*4:]

    var k1 uint32
    switch len(tail) & 3 {
    case 3:
        k1 ^= uint32(tail[2]) << 16
        fallthrough
    case 2:
        k1 ^= uint32(tail[1]) << 8
        fallthrough
    case 1:
        k1 ^= uint32(tail[0])
        k1 *= c1_32
        k1 = (k1 << 15) | (k1 >> 17) // rotl32(k1, 15)
        k1 *= c2_32
        h1 ^= k1
    }

    h1 ^= uint32(len(data))

    h1 ^= h1 >> 16
    h1 *= 0x85ebca6b
    h1 ^= h1 >> 13
    h1 *= 0xc2b2ae35
    h1 ^= h1 >> 16

    return h1
}
// Hash_fnv calculates string hash value using FNV-1a algorithm
// Parameters:
//   - s: string to calculate hash
// Returns:
//   - 32-bit hash value
func Hash_fnv(s string) uint32 {
    h := fnv.New32a()
    h.Write([]byte(s))
    return h.Sum32()
}
