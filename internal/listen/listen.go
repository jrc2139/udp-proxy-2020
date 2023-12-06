package listen

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	log "github.com/phuslu/log"

	"github.com/synfinatic/udp-proxy-2020/internal/send"
)

const (
	SEND_BUFFER_SIZE = 100
	MAX_PACKET_SIZE  = 8192
)

// Struct containing everything for an interface
type Listen struct {
	IName     string               // interface to use
	netif     *net.Interface       // interface descriptor
	Ports     []int32              // port(s) we listen for packets
	ipaddr    string               // dstip we send packets to
	Promisc   bool                 // do we enable promisc on this interface?
	Handle    *pcap.Handle         // gopacket.pcap handle
	writer    *pcapgo.Writer       // in and outbound write packet handle
	inwriter  *pcapgo.Writer       // inbound write packet handle
	outwriter *pcapgo.Writer       // outbound write packet handle
	sendOnly  bool                 // Only send on this interface
	localIP   net.IP               // the local interface IP
	Timeout   time.Duration        // timeout for loop
	ClientTTL time.Duration        // ttl for client cache
	Sendpkt   chan send.Send       // channel used to receive packets we need to send
	clients   map[string]time.Time // keep track of clients for non-promisc interfaces
}

// List of LayerTypes we support in sendPacket()
var validLinkTypes = []layers.LinkType{
	layers.LinkTypeLoop,
	layers.LinkTypeEthernet,
	layers.LinkTypeNull,
	layers.LinkTypeRaw,
}

// Creates a Listen struct for the given interface, promisc mode, udp sniff ports and timeout
func NewListener(
	netif *net.Interface,
	promisc, sendOnly bool,
	ports []int32,
	to time.Duration,
	fixed_ip []string,
) Listen {
	var localip net.IP

	log.Debug().Msgf("%s: ifIndex: %d", netif.Name, netif.Index)
	addrs, err := netif.Addrs()
	if err != nil {
		log.Fatal().Msgf("Unable to obtain addresses for %s", netif.Name)
	}
	var bcastaddr string
	// only calc the broadcast address on promiscuous interfaces
	// for non-promisc, we use our clients
	if !promisc {
		for _, addr := range addrs {
			log.Debug().
				Msgf("%s network: %s\t\tstring: %s", netif.Name, addr.Network(), addr.String())

			_, ipNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				log.Debug().
					Msgf("%s: Unable to parse CIDR: %s (%s)", netif.Name, addr.String(), addr.Network())
				continue
			}
			if ipNet.IP.To4() == nil {
				continue // Skip non-IPv4 addresses
			}
			// calc broadcast
			ip := make(net.IP, len(ipNet.IP.To4()))
			bcastbin := binary.BigEndian.Uint32(
				ipNet.IP.To4(),
			) | ^binary.BigEndian.Uint32(
				net.IP(ipNet.Mask).To4(),
			)
			binary.BigEndian.PutUint32(ip, bcastbin)
			bcastaddr = ip.String()
		}
		// promisc interfaces should have a bcast/ipv4 config
		if len(bcastaddr) == 0 && promisc {
			log.Fatal().Msgf("%s does not have a valid IPv4 configuration", netif.Name)
		}
	}

	// fixed ip clients
	clients := make(map[string]time.Time)
	for _, ip := range fixed_ip {
		clients[ip] = time.Time{} // zero value
	}

	newL := Listen{
		IName:    netif.Name,
		netif:    netif,
		localIP:  localip,
		sendOnly: sendOnly,
		Ports:    ports,
		ipaddr:   bcastaddr,
		Timeout:  to,
		Promisc:  promisc,
		Handle:   nil,
		Sendpkt:  make(chan send.Send, SEND_BUFFER_SIZE),
		clients:  clients,
	}

	log.Debug().Msgf("Listen: %s", spew.Sdump(newL))
	return newL
}

type Direction string

const (
	In    Direction = "in"
	Out   Direction = "out"
	InOut Direction = "inout"
)

// OpenWrite will open the write file pcap handle
func (l *Listen) OpenWriter(path string, dir Direction) (string, error) {
	var err error
	fName := fmt.Sprintf("udp-proxy-%s-%s.pcap", dir, l.IName)
	filePath := filepath.Join(path, fName)
	f, err := os.Create(filePath)
	if err != nil {
		return fName, err
	}
	switch dir {
	case "in":
		l.inwriter = pcapgo.NewWriter(f)
		return fName, l.inwriter.WriteFileHeader(65536, l.Handle.LinkType())
	case "out":
		l.outwriter = pcapgo.NewWriter(f)
		return fName, l.outwriter.WriteFileHeader(65536, l.Handle.LinkType())
	case "inout":
		l.writer = pcapgo.NewWriter(f)
		return fName, l.writer.WriteFileHeader(65536, l.Handle.LinkType())
	}
	return fName, fmt.Errorf("invalid direction: %s", dir)
}

// Our goroutine for processing packets
func (l *Listen) HandlePackets(s *send.SendPktFeed, wg *sync.WaitGroup) {
	// add ourself as a sender
	s.RegisterSender(l.Sendpkt, l.IName)

	// get packets from libpcap
	packetSource := gopacket.NewPacketSource(l.Handle, l.Handle.LinkType())
	packets := packetSource.Packets()

	// This timer is nice for debugging
	d, _ := time.ParseDuration("5s")
	ticker := time.NewTicker(d)
	defer ticker.Stop()

	// loop forever and ever and ever
	for {
		select {
		case s := <-l.Sendpkt: // packet arrived from another interface
			l.sendPackets(s)
		case packet := <-packets: // packet arrived on this interfaces
			// ignore packets on this interface??
			if l.sendOnly {
				continue
			}

			// is it legit?
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil ||
				packet.TransportLayer().LayerType() != layers.LayerTypeUDP {
				log.Warn().Msgf("%s: Invalid packet", l.IName)
				continue
			} else if errx := packet.ErrorLayer(); errx != nil {
				log.Error().Msgf("%s: Unable to decode: %s", l.IName, errx.Error())
			}

			// if our interface is non-promisc, learn the client IP
			if l.Promisc {
				l.learnClientIP(packet)
			}

			log.Debug().Msgf("%s: received packet and forwarding onto other interfaces", l.IName)
			s.Send(packet, l.IName, l.Handle.LinkType())

			// write to pcap?
			if l.inwriter != nil {
				md := packet.Metadata()
				ci := gopacket.CaptureInfo{
					Timestamp:      md.Timestamp,
					CaptureLength:  md.CaptureLength,
					Length:         md.Length,
					InterfaceIndex: md.InterfaceIndex,
					AncillaryData:  md.AncillaryData,
				}
				if err := l.inwriter.WritePacket(ci, packet.Data()); err != nil {
					log.Warn().Err(err).Msgf("Unable to write packet to pcap file")
				}
				if err := l.writer.WritePacket(ci, packet.Data()); err != nil {
					log.Warn().Err(err).Msgf("Unable to write packet to pcap file")
				}
			}

		case <-ticker.C: // our timer
			log.Debug().Msgf("handlePackets(%s) ticker", l.IName)
			// clean client cache
			for k, v := range l.clients {
				// zero is hard code values
				if !v.IsZero() && v.Before(time.Now()) {
					log.Debug().Msgf("%s removing %s after %dsec", l.IName, k, l.ClientTTL)
					delete(l.clients, k)
				}
			}
		}
	}
}

func (l *Listen) decodePacket(sndpkt send.Send, eth *layers.Ethernet, loop *layers.Loopback,
	ip4 *layers.IPv4, udp *layers.UDP, payload *gopacket.Payload,
) bool {
	var parser *gopacket.DecodingLayerParser

	log.Debug().Msgf("processing packet from %s on %s", sndpkt.Srcif, l.IName)

	switch sndpkt.LinkType.String() {
	case layers.LinkTypeNull.String(), layers.LinkTypeLoop.String():
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeLoopback, loop, ip4, udp, payload)
	case layers.LinkTypeEthernet.String():
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, eth, ip4, udp, payload)
	case layers.LinkTypeRaw.String():
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, ip4, udp, payload)
	default:
		log.Fatal().Msgf("Unsupported source linktype: %s", sndpkt.LinkType.String())
	}

	// try decoding our packet
	decoded := []gopacket.LayerType{}
	if err := parser.DecodeLayers(sndpkt.Packet.Data(), &decoded); err != nil {
		log.Warn().Msgf("Unable to decode packet from %s: %s", sndpkt.Srcif, err)
		return false
	}

	// was packet decoded?  In theory, this should never happen because our BPF filter...
	found_udp := false
	found_ipv4 := false
	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeUDP:
			found_udp = true
		case layers.LayerTypeIPv4:
			found_ipv4 = true
		}
	}
	if !found_udp || !found_ipv4 {
		log.Warn().Msgf("Packet from %s did not contain a IPv4/UDP packet", sndpkt.Srcif)
		return false
	}

	return true
}

// Does the heavy lifting of editing & sending the packet onwards
func (l *Listen) sendPackets(sndpkt send.Send) {
	var eth layers.Ethernet
	var loop layers.Loopback // BSD NULL/Loopback used for OpenVPN tunnels/etc
	var ip4 layers.IPv4      // we only support v4
	var udp layers.UDP
	var payload gopacket.Payload

	if decoded := l.decodePacket(sndpkt, &eth, &loop, &ip4, &udp, &payload); !decoded {
		// unable to decode packet, ignore it
		return
	}

	if !l.Promisc {
		// send one packet to broadcast IP
		dstip := net.ParseIP(l.ipaddr).To4()
		if bytes, err := l.sendPacket(sndpkt, dstip, eth, loop, ip4, udp, payload); err != nil {
			log.Warn().Msgf("Unable to send %d bytes from %s out %s: %s",
				bytes, sndpkt.Srcif, l.IName, err)
		}
	} else {
		// sent packet to every client
		if len(l.clients) == 0 {
			log.Debug().Msgf("%s: Unable to send packet; no discovered clients", l.IName)
		}
		for ip := range l.clients {
			dstip := net.ParseIP(ip).To4()
			if bytes, err := l.sendPacket(sndpkt, dstip, eth, loop, ip4, udp, payload); err != nil {
				log.Warn().Msgf("Unable to send %d bytes from %s out %s: %s",
					bytes, sndpkt.Srcif, l.IName, err)
			}
		}
	}
}

func (l *Listen) buildPacket(
	sndpkt send.Send,
	dstip net.IP,
	eth layers.Ethernet,
	loop layers.Loopback,
	ip4 layers.IPv4,
	udp layers.UDP,
	payload gopacket.Payload,
	opts gopacket.SerializeOptions,
) gopacket.SerializeBuffer {
	// Build our packet to send
	buffer := gopacket.NewSerializeBuffer()
	csum_opts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true, // only works for IPv4
	}
	// UDP payload
	if err := payload.SerializeTo(buffer, opts); err != nil {
		log.Fatal().Msgf("can't serialize payload: %s", spew.Sdump(payload))
	}

	// UDP checksums can't be calculated via SerializeOptions
	// because it requires the IP pseudo-header:
	// https://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv4_pseudo_header
	new_udp := layers.UDP{
		SrcPort:  udp.SrcPort,
		DstPort:  udp.DstPort,
		Checksum: 0, // but 0 is always valid for UDP
		Length:   uint16(8 + len(payload)),
	}

	if err := new_udp.SerializeTo(buffer, opts); err != nil {
		log.Fatal().Msgf("can't serialize UDP header: %s", spew.Sdump(udp))
	}

	// IPv4 header
	new_ip4 := layers.IPv4{
		Version:    ip4.Version,
		IHL:        ip4.IHL,
		TOS:        ip4.TOS,
		Length:     ip4.Length,
		Id:         ip4.Id,
		Flags:      ip4.Flags,
		FragOffset: ip4.FragOffset,
		TTL:        ip4.TTL,
		Protocol:   ip4.Protocol,
		Checksum:   0, // reset to calc checksums
		SrcIP:      ip4.SrcIP,
		DstIP:      dstip,
		Options:    ip4.Options,
	}
	if err := new_ip4.SerializeTo(buffer, csum_opts); err != nil {
		log.Fatal().Msgf("can't serialize IP header: %s", spew.Sdump(new_ip4))
	}
	return buffer
}

func (l *Listen) sendPacket(
	sndpkt send.Send,
	dstip net.IP,
	eth layers.Ethernet,
	loop layers.Loopback,
	ip4 layers.IPv4,
	udp layers.UDP,
	payload gopacket.Payload,
) (int, error) {
	opts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: false,
	}
	buffer := l.buildPacket(sndpkt, dstip, eth, loop, ip4, udp, payload, opts)

	// Add our L2 header to the buffer
	switch l.Handle.LinkType().String() {
	case layers.LinkTypeNull.String(), layers.LinkTypeLoop.String():
		loop := layers.Loopback{
			Family: layers.ProtocolFamilyIPv4,
		}
		if err := loop.SerializeTo(buffer, opts); err != nil {
			log.Fatal().Msgf("can't serialize Loop header: %s", spew.Sdump(loop))
		}
	case layers.LinkTypeEthernet.String():
		// build a new ethernet header
		new_eth := layers.Ethernet{
			BaseLayer:    layers.BaseLayer{},
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			SrcMAC:       l.netif.HardwareAddr,
			EthernetType: layers.EthernetTypeIPv4,
		}
		if err := new_eth.SerializeTo(buffer, opts); err != nil {
			log.Fatal().Msgf("can't serialize Eth header: %s", spew.Sdump(new_eth))
		}
	case layers.LinkTypeRaw.String():
		// no L2 header
	default:
		log.Warn().Msgf("Unsupported linktype: %s", l.Handle.LinkType().String())
	}

	outgoingPacket := buffer.Bytes()
	log.Debug().Msgf("%s => %s: packet len: %d", l.IName, dstip.String(), len(outgoingPacket))

	// write to pcap?
	if l.outwriter != nil {
		md := sndpkt.Packet.Metadata()
		ci := gopacket.CaptureInfo{
			Timestamp:      md.Timestamp,
			CaptureLength:  len(outgoingPacket),
			Length:         len(outgoingPacket),
			InterfaceIndex: md.InterfaceIndex,
			AncillaryData:  md.AncillaryData,
		}
		if err := l.outwriter.WritePacket(ci, outgoingPacket); err != nil {
			log.Warn().Err(err).Msgf("Unable to write packet to pcap file")
		}
		if err := l.writer.WritePacket(ci, outgoingPacket); err != nil {
			log.Warn().Err(err).Msgf("Unable to write packet to pcap file")
		}
	}

	return len(outgoingPacket), l.Handle.WritePacketData(outgoingPacket)
}

func (l *Listen) learnClientIP(packet gopacket.Packet) {
	var eth layers.Ethernet
	var loop layers.Loopback
	var ip4 layers.IPv4
	var udp layers.UDP
	var payload gopacket.Payload
	var parser *gopacket.DecodingLayerParser

	switch l.Handle.LinkType().String() {
	case layers.LinkTypeNull.String(), layers.LinkTypeLoop.String():
		parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeLoopback,
			&loop,
			&ip4,
			&udp,
			&payload,
		)
	case layers.LinkTypeEthernet.String():
		parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&eth,
			&ip4,
			&udp,
			&payload,
		)
	case layers.LinkTypeRaw.String():
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &udp, &payload)
	default:
		log.Fatal().Msgf("Unsupported source linktype: %s", l.Handle.LinkType().String())
	}

	decoded := []gopacket.LayerType{}
	if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
		log.Debug().Msgf("Unable to decoded client IP on %s: %s", l.IName, err)
	}

	found_ipv4 := false
	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeIPv4:
			// found our v4 header
			found_ipv4 = true
		}
	}

	if found_ipv4 {
		val, exists := l.clients[ip4.SrcIP.String()]
		if !exists || !val.IsZero() {
			l.clients[ip4.SrcIP.String()] = time.Now().Add(l.ClientTTL)
			log.Debug().Msgf("%s: Learned client IP: %s", l.IName, ip4.SrcIP.String())
		}
	}
}

// Returns if the provided layertype is valid
func IsValidLayerType(layertype layers.LinkType) bool {
	for _, b := range validLinkTypes {
		if strings.Compare(b.String(), layertype.String()) == 0 {
			return true
		}
	}
	return false
}

// SinkUdpPackets opens a UDP socket for broadcast packets and sends them to /dev/null
// creates a go-routine for each interface/port combo so we don't block
func (l *Listen) SinkUdpPackets() error {
	addrs, err := l.netif.Addrs()
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		addrs := addr.String()

		// skip anything that doesn't look like a unicast IPv4 address
		if addrs == "0.0.0.0" || addrs == "" || strings.Contains(addrs, ":") {
			continue
		}
		ipport := strings.Split(addrs, "/")
		for _, port := range l.Ports {
			udp := net.UDPAddr{
				IP:   net.ParseIP(ipport[0]),
				Port: int(port),
			}

			conn, err := net.ListenUDP("udp4", &udp)
			if err != nil {
				return fmt.Errorf("%s:%d: %s", ipport[0], port, err.Error())
			}

			if err := conn.SetReadBuffer(MAX_PACKET_SIZE); err != nil {
				return err
			}

			go func() {
				buff := make([]byte, MAX_PACKET_SIZE)
				for {
					_, _, err := conn.ReadFromUDP(buff)
					if err != nil {
						log.Warn().Err(err).Msg("Unable to read broadcast packet")
					}
					// do nothing with the data
				}
			}()
		}
	}
	return nil
}
