package controllers

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/crowdsecurity/crowdsec/cmd/api/ent"
	"net"
	"time"
)

type Controller struct {
	Ectx   context.Context
	Client *ent.Client
}

type AlertInput struct {
	MachineId  string     `json:"machine_id" binding:"required"`
	Scenario   string     `json:"scenario" binding:"required"`
	BucketId   string     `json:"bucket_id" binding:"required"`
	Message    string     `json:"message" binding:"required"`
	EventCount int        `json:"event_count" binding:"required"`
	StartedAt  time.Time  `json:"started_at" binding:"required"`
	StoppedAt  time.Time  `json:"stopped_at" binding:"required"`
	Capacity   int        `json:"capacity" binding:"required"`
	LeakSpeed  int        `json:"leak_speed" binding:"required"`
	Reprocess  bool       `json:"reprocess"`
	Source     Source     `json:"source" binding:"required"`
	Events     []Event    `json:"events" binding:"required"`
	Metas      []Meta     `json:"metas"`
	Decisions  []Decision `json:"decisions" binding:"required"`
}

type Event struct {
	Time       time.Time `json:"time"`
	Serialized string    `json:"serialized"`
}

type Source struct {
	Scope     string  `json:"scope" binding:"required"`
	Value     string  `json:"value" binding:"required"`
	Ip        string  `json:"ip"`
	Range     string  `json:"range"`
	AsNumber  string  `json:"as_number"`
	AsName    string  `json:"as_name"`
	Country   string  `json:"country"`
	Latitude  float32 `json:"latitude"`
	Longitude float32 `json:"longitude"`
}

type Meta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Decision struct {
	Until         time.Time `json:"until"`
	Scenario      string    `json:"scenario"`
	DecisionType  string    `json:"decision_type"`
	SourceIpStart uint32    `json:"source_ip_start"`
	SourceIpEnd   uint32    `json:"source_ip_end"`
	SourceValue   string    `json:"source_value"`
	SourceScope   string    `json:"source_scope"`
}

func IP2Int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func Int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func IsIpv4(host string) bool {
	return net.ParseIP(host) != nil
}

//Stolen from : https://github.com/llimllib/ipaddress/
// Return the final address of a net range. Convert to IPv4 if possible,
// otherwise return an ipv6
func LastAddress(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil {
		ip = n.IP
		return net.IP{
			ip[0] | ^n.Mask[0], ip[1] | ^n.Mask[1], ip[2] | ^n.Mask[2],
			ip[3] | ^n.Mask[3], ip[4] | ^n.Mask[4], ip[5] | ^n.Mask[5],
			ip[6] | ^n.Mask[6], ip[7] | ^n.Mask[7], ip[8] | ^n.Mask[8],
			ip[9] | ^n.Mask[9], ip[10] | ^n.Mask[10], ip[11] | ^n.Mask[11],
			ip[12] | ^n.Mask[12], ip[13] | ^n.Mask[13], ip[14] | ^n.Mask[14],
			ip[15] | ^n.Mask[15]}
	}

	return net.IPv4(
		ip[0]|^n.Mask[0],
		ip[1]|^n.Mask[1],
		ip[2]|^n.Mask[2],
		ip[3]|^n.Mask[3])
}

func GetIpsFromIpRange(host string) (uint32, uint32, error) {
	var ipStart uint32
	var ipEnd uint32
	var err error
	var parsedRange *net.IPNet

	if _, parsedRange, err = net.ParseCIDR(host); err != nil {
		return ipStart, ipEnd, fmt.Errorf("'%s' is not a valid CIDR", host)
	}
	if parsedRange == nil {
		return ipStart, ipEnd, fmt.Errorf("unable to parse network : %s", err)
	}
	ipStart = IP2Int(parsedRange.IP)
	ipEnd = IP2Int(LastAddress(parsedRange))
	return ipStart, ipEnd, nil
}
