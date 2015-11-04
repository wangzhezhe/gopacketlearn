package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"strings"
	"time"
)

var (
	device       string = "eth0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 2 * time.Second
	handle       *pcap.Handle
	// Will reuse these for each packet
	ethLayer layers.Ethernet
	ipLayer  layers.IPv4
	tcpLayer layers.TCP
)

func checkLocalip(iface string) (string, error) {
	ifaceobj, err := net.InterfaceByName(iface)
	if err != nil {
		return "", err
	}
	addrarry, err := ifaceobj.Addrs()
	if err != nil {
		return "", err
	}
	var localip = ""
	fmt.Println(addrarry)
	for _, ip := range addrarry {
		IP := ip.String()
		if strings.Contains(IP, "/24") {
			localip = strings.TrimSuffix(IP, "/24")
		}
	}

	return localip, nil
}

func main() {
	//get local ip
	localip, err := checkLocalip(device)

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
		)
		foundLayerTypes := []gopacket.LayerType{}

		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			fmt.Println("Trouble decoding layers: ", err)
		}

		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeIPv4 {
				fmt.Println("IPV4 found")
			}
			if ipLayer.DstIP.String() == localip || ipLayer.SrcIP.String() == localip {
				fmt.Println("IPv4 go through this machine: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
				applicationLayer := packet.ApplicationLayer()
				if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
					fmt.Println("HTTP found!")
					fmt.Println("layer content", string(applicationLayer.LayerContents()))
					fmt.Println("layer payload", string(applicationLayer.Payload()))
					fmt.Println("layer type", string(applicationLayer.LayerType()))
				}
			}

		}

	}
}

/*
	if layerType == layers.LayerTypeIPv4 {
		fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
	}

	if ipLayer.DstIP.String() == localip {
		if ipLayer.DstIP.String() == "10.10.103.131" {

			if layerType == layers.LayerTypeIPv4 {
				fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
				applicationLayer := packet.ApplicationLayer()
				if applicationLayer != nil {
					fmt.Println("Application layer/Payload found.")
					//fmt.Printf("%s\n", applicationLayer.Payload())
					fmt.Printf("%v\n", string(applicationLayer.Payload()))

					// Search for a string inside the payload
					if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
						fmt.Println("HTTP found!")
						fmt.Println("layer content", string(applicationLayer.LayerContents()))
						fmt.Println("layer payload", string(applicationLayer.Payload()))
						fmt.Println("layer type", string(applicationLayer.LayerType()))
					}
				}

			}

			if layerType == layers.LayerTypeTCP {
				fmt.Println("TCP Port: ", tcpLayer.SrcPort, "->", tcpLayer.DstPort)
				fmt.Println("TCP SYN:", tcpLayer.SYN, " | ACK:", tcpLayer.ACK)
				fmt.Println("content ", string(tcpLayer.Contents))
				fmt.Println("info", tcpLayer.ECE)
			}
*/
