package controllers

import (
	"encoding/binary"
	"net"
	"net/http"

	"github.com/crowdsecurity/crowdsec/cmd/api/ent/decision"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

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

func (c *Controller) FindDecisionByIp(gctx *gin.Context) {
	ip := gctx.Param("ipText")

	isValidIp := IsIpv4(ip)
	if !isValidIp {
		log.Errorf("failed querying decision: Ip %v is not valid", ip)
		gctx.JSON(http.StatusBadRequest, gin.H{"error": "ipText is not valid"})
		return
	}

	decisions, err := c.Client.Debug().Decision.Query().
		Where(decision.SourceValueEQ(ip)).
		All(c.Ectx)
	if err != nil {
		log.Errorf("failed querying decision: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed querying decision"})
		return
	}

	gctx.JSON(http.StatusOK, gin.H{"data": decisions})
	return
}

func (c *Controller) GetDecision(gctx *gin.Context) {
	gctx.JSON(http.StatusOK, gin.H{"message": "YOU ARE ALLOWED MY FRIEND"})
}
