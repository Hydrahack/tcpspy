package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	list      = flag.Bool("l", false, `Network Interface List.`)
	iface     = flag.String("i", "", "Network Interface Name")
	port      = flag.Int("p", 80, "Port Default 80")
	size      = flag.Int("s", 1024, "Packet Size Default 1024")
	filterstr = flag.String("f", "", "filter String")
	outfile   = flag.String("o", "", "Pcap Outfile Path")
)

func main() {
	fmt.Println("tcpspy by:steeltiger")
	flag.Parse()

	if *list {
		golist()
	}

	if *iface != "" {
		gopack(*iface, uint16(*port), int32(*size), *filterstr, *outfile)
	}

}

func golist() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	fmt.Println("Devices found:")
	for _, d := range devices {
		fmt.Println("\nName: ", d.Name)
		fmt.Println("Description: ", d.Description)
		fmt.Println("Devices addresses: ", d.Description)

		for _, address := range d.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}

func gopack(netname string, portstr uint16, snapLenstr int32, filterstr string, out string) {
	fmt.Println("packet start...")

	deviceName := netname
	snapLen := snapLenstr
	port := portstr
	filter := getFilter(port)
	fmt.Printf("device:%v, snapLen:%v, port:%v\n", deviceName, snapLen, port)
	fmt.Println("filter:", filter)

	//打开网络接口，抓取在线数据
	handle, err := pcap.OpenLive(deviceName, snapLen, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("pcap open live failed: %v", err)
		return
	}

	// 设置过滤器
	if err := handle.SetBPFFilter(filter); err != nil {
		fmt.Printf("set bpf filter failed: %v", err)
		return
	}
	defer handle.Close()

	f, _ := os.Create(out)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(uint32(handle.SnapLen()*1), handle.LinkType())
	defer f.Close()

	// 抓包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	for packet := range packetSource.Packets() {
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			fmt.Println("unexpected packet")
			continue
		}

		//fmt.Printf("packet:%v\n",packet)

		layertype := packet.NetworkLayer().LayerType()
		//fmt.Println(layertype.String())
		if layertype.String() == "IPv4" {
			//IP层
			ip4 := packet.NetworkLayer().(*layers.IPv4)
			//ip6 := packet.NetworkLayer().(*layers.IPv6)
			// tcp 层
			tcp := packet.TransportLayer().(*layers.TCP)
			//fmt.Printf("tcp:%v\n", tcp)
			// tcp payload，也即是tcp传输的数据

			if out != "" {
				w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			}

			Payload := string(tcp.Payload)

			if strings.HasPrefix(Payload, filterstr) && out == "" {

				reg := regexp.MustCompile(`(?s)(GET|POST) (.*?) HTTP.*Host: (.*?)\n`)
				result := reg.FindStringSubmatch(Payload)
				if len(result) > 2 {
					fmt.Printf("from %s:%s to %s:%s host:%s \n", ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort, result[3])
				} else {
					fmt.Printf("from %s:%s to %s:%s\n", ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort)
				}
				fmt.Printf("payload:%v\n------------------------------------------------\n\n", Payload)
			}
		}

	}

}

//定义过滤器
func getFilter(port uint16) string {
	filter := fmt.Sprintf("tcp and ((src port %v) or (dst port %v))", port, port)
	return filter
}
