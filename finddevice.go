package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
)

func main() {
	// Find all devices
	devices, err := pcap.FindAllDevs()

	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	fmt.Println("Devices found:")
	fmt.Println(devices)
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}

	//or use the net.interfaces direactly (do not use root privilages)
	newdevices, _ := net.Interfaces()
	for _, device := range newdevices {
		fmt.Printf("%v\n", device)
	}

}
