package interfaces

import (
	"fmt"

	"github.com/google/gopacket/pcap"
	log "github.com/phuslu/log"

	"github.com/synfinatic/udp-proxy-2020/internal/listen"
	"github.com/synfinatic/udp-proxy-2020/internal/utils"
)

// Interfaces is a map between interface name and pcap data structure
var Interfaces = map[string]pcap.Interface{}

func InitializeInterface(l *listen.Listen) {
	// find our interface via libpcap
	getConfiguredInterfaces()
	if len(Interfaces[l.IName].Addresses) == 0 {
		log.Fatal().Msgf("%s is not configured", l.IName)
	}

	// configure libpcap listener
	inactive, err := pcap.NewInactiveHandle(l.IName)
	if err != nil {
		log.Fatal().Msgf("%s: %s", l.IName, err)
	}
	defer inactive.CleanUp()

	// set our timeout
	if err = inactive.SetTimeout(l.Timeout); err != nil {
		log.Fatal().Msgf("%s: %s", l.IName, err)
	}

	// Promiscuous mode on/off
	if err = inactive.SetPromisc(l.Promisc); err != nil {
		log.Fatal().Msgf("%s: %s", l.IName, err)
	}
	// Get the entire packet
	if err = inactive.SetSnapLen(9000); err != nil {
		log.Fatal().Msgf("%s: %s", l.IName, err)
	}

	// activate libpcap handle
	if l.Handle, err = inactive.Activate(); err != nil {
		log.Fatal().Msgf("%s: %s", l.IName, err)
	}

	if !listen.IsValidLayerType(l.Handle.LinkType()) {
		log.Fatal().Msgf("%s: has an invalid layer type: %s", l.IName, l.Handle.LinkType().String())
	}

	// set our BPF filter
	bpf_filter := utils.BuildBPFFilter(l.Ports, Interfaces[l.IName].Addresses, l.Promisc)
	log.Debug().Msgf("%s: applying BPF Filter: %s", l.IName, bpf_filter)
	if err = l.Handle.SetBPFFilter(bpf_filter); err != nil {
		log.Fatal().Msgf("%s: %s", l.IName, err)
	}

	// just inbound packets
	if err = l.Handle.SetDirection(pcap.DirectionIn); err != nil {
		log.Fatal().Msgf("%s: %s", l.IName, err)
	}

	log.Debug().Msgf("Opened pcap handle on %s", l.IName)
}

// Uses libpcap to get a list of configured interfaces
// and populate the Interfaces.
func getConfiguredInterfaces() {
	if len(Interfaces) > 0 {
		return
	}
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal().Err(err)
	}
	for _, i := range ifs {
		if len(i.Addresses) == 0 {
			continue
		}
		Interfaces[i.Name] = i
	}
}

// Print out a list of all the interfaces that libpcap sees
func ListInterfaces() {
	getConfiguredInterfaces()
	for k, v := range Interfaces {
		fmt.Printf("Interface: %s\n", k)
		for _, a := range v.Addresses {
			ones, _ := a.Netmask.Size()
			if a.Broadaddr != nil {
				fmt.Printf("\t- IP: %s/%d  Broadaddr: %s\n",
					a.IP.String(), ones, a.Broadaddr.String())
			} else if a.P2P != nil {
				fmt.Printf("\t- IP: %s/%d  PointToPoint: %s\n",
					a.IP.String(), ones, a.P2P.String())
			} else {
				fmt.Printf("\t- IP: %s/%d\n", a.IP.String(), ones)
			}
		}
		fmt.Printf("\n")
	}
}

// getLoopback returns the name of the loopback interface
func GetLoopback() string {
	getConfiguredInterfaces()
	for k, v := range Interfaces {
		for _, a := range v.Addresses {
			if a.IP.String() == "127.0.0.1" {
				return k
			}
		}
	}
	return "No Loopback Interface"
}
