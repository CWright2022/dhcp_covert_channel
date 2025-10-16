package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

const (
	//address to send requests to
	serverAddress = "127.0.0.1"
	//custom transaction ID (leave blank for random)
	transactionID = ""
)

func main() {

	//get secret message (can adapt this later)
	var message string
	fmt.Println("Enter the secret message to send:")
	fmt.Scanf("%s", &message)
	message = base64.StdEncoding.EncodeToString([]byte(message))

	//generate random transaction ID (if needed)
	var tid []byte
	if transactionID == "" {
		tidBytes := make([]byte, 4)
		_, err := rand.Read(tidBytes)
		if err != nil {
			log.Fatalf("Error generating transaction ID: %v", err)
		}
		tid = tidBytes
	}

	//create packet
	packet, err := dhcpv4.New(dhcpv4.WithTransactionID(dhcpv4.TransactionID(tid)))
	if err != nil {
		log.Fatalf("Error creating DHCP packet: %v", err)
	}

	//set all initial options
	packet.Options.Update(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
	packet.Options.Update(dhcpv4.OptIPAddressLeaseTime(time.Second*0))

}
