package main

import (
	"container/list"
	"flag"
	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	device           string = "eth0"
	snapshotLen      int32  = 1024
	promiscuous      bool   = false
	err              error
	timeout          time.Duration = 2 * time.Second
	handle           *pcap.Handle
	localip          string
	httpinstancelist *list.List
)

type HttpTransaction struct {
	Srcip       string
	Srcport     string
	Destip      string
	Destport    string
	Timesend    time.Time
	Timereceive time.Time
}

type Address struct {
	IP   string
	PORT string
}

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
	if glog.V(1) {
		glog.Info(addrarry)
	}
	for _, ip := range addrarry {
		IP := ip.String()
		if strings.Contains(IP, "/24") {
			localip = strings.TrimSuffix(IP, "/24")
		}
	}

	return localip, nil
}

//detect the http packet return the info
func detectHttp(packet gopacket.Packet) (bool, []byte) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {

			if glog.V(1) {
				glog.Info("HTTP found!")
			}
			return true, applicationLayer.LayerContents()
		} else {
			return false, nil
		}
	} else {
		return false, nil
	}
}

//if it is the input stream from local machine
func outputStream(packet gopacket.Packet, Srcaddr *Address, Destaddr *Address) {
	ishttp, httpcontent := detectHttp(packet)
	if httpcontent != nil {
		if glog.V(1) {
			glog.Info("the content of packet sent:", string(httpcontent))
		}
	}

	if ishttp {
		sendtime := time.Now()
		//iphandler := packet.Layer(layers.LayerTypeIPv4)
		httpinstance := &HttpTransaction{Srcip: Srcaddr.IP,
			Srcport:  Srcaddr.PORT,
			Destip:   Destaddr.IP,
			Destport: Destaddr.PORT,
			Timesend: sendtime,
		}

		//put the httpinstance into a list
		if glog.V(1) {
			glog.Infof("store the instance:%v\n", httpinstance)
		}
		httpinstancelist.PushBack(httpinstance)
		if glog.V(2) {
			glog.Infof("the length of the list :", httpinstancelist.Len())
		}
	}

}

//adjust if this is the response of the packet
func ifreverse(httpinstance *HttpTransaction, Srcaddr *Address, Destaddr *Address) bool {
	if httpinstance.Srcip == Destaddr.IP && httpinstance.Destip == Srcaddr.IP {
		if httpinstance.Srcport == Destaddr.PORT && httpinstance.Destport == Srcaddr.PORT {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}

//if it is the input stream from local machine
func inputStream(packet gopacket.Packet, Srcaddr *Address, Destaddr *Address) {
	//get the instance from the list which has the reverse srcaddr and the destaddr
	if glog.V(1) {
		glog.Info("the length of the list before extract element:", httpinstancelist.Len())
	}

	for element := httpinstancelist.Front(); element != nil; element = element.Next() {
		httpinstance := element.Value.(*HttpTransaction)
		isreverse := ifreverse(httpinstance, Srcaddr, Destaddr)
		if isreverse {
			httpinstance.Timereceive = time.Now()
			if glog.V(0) {
				glog.Infof("get the response: %v", httpinstance)
				glog.Infof("respond duration:%vms", httpinstance.Timereceive.Sub(httpinstance.Timesend).Seconds()*1000)
			}
			httpinstancelist.Remove(element)
			break
		}
	}

}

//every time get a new packet
func processPacketInfo(packet gopacket.Packet) {
	//get the specified layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		if glog.V(2) {
			glog.Info("TCP layer is detected.")
		}

		tcphandler, _ := tcpLayer.(*layers.TCP)
		srcport := tcphandler.SrcPort
		destport := tcphandler.DstPort
		//get the specified layer
		iplayer := packet.Layer(layers.LayerTypeIPv4)
		httphandler, _ := iplayer.(*layers.IPv4)
		srcip := httphandler.SrcIP
		destip := httphandler.DstIP
		//log.Println(srcip.String())
		//send the packet from local machine
		Srcaddr := &Address{IP: srcip.String(), PORT: srcport.String()}
		Destaddr := &Address{IP: destip.String(), PORT: destport.String()}
		var mutex = &sync.Mutex{}

		if srcip.String() == localip {
			mutex.Lock()
			outputStream(packet, Srcaddr, Destaddr)
			mutex.Unlock()
		}
		//get the packet from the local machine
		if destip.String() == localip {

			mutex.Lock()
			inputStream(packet, Srcaddr, Destaddr)
			mutex.Unlock()
		}

	}
}

func main() {
	flag.Parse()
	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		glog.Info(err.Error())
	}

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	templocalip, err := checkLocalip(device)
	localip = templocalip
	if glog.V(0) {
		glog.Info(localip)
	}
	httpinstancelist = list.New()
	if err != nil {
		glog.Info(err.Error())
	}
	for packet := range packetSource.Packets() {
		processPacketInfo(packet)
	}
}
