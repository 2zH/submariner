package kcpvpn

import (
	"fmt"
	"net"
	"sync"

	"github.com/kelseyhightower/envconfig"
	"github.com/submariner-io/admiral/pkg/log"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	"github.com/submariner-io/submariner/pkg/types"
	"k8s.io/klog"
)

const (
	cableDriverName = "kcpvpn"
	socatIFace      = "socat-tunnel"

	specEnvPrefix = "ce_ipsec"
)

type specification struct {
	PSK      string `default:"default psk"`
	NATTPort int    `default:"4500"`
	LogFile  string
	Debug    bool
}

type kcpvpn_driver struct {
	localEndpoint types.SubmarinerEndpoint
	connections   map[string]*v1.Connection // clusterID -> remote ep connection
	mutex         sync.Mutex

	spec *specification
}

func init() {
	cable.AddDriver(cableDriverName, NewKCPTun)
}

func NewKCPTun(localEndpoint types.SubmarinerEndpoint, localCluster types.SubmarinerCluster) (cable.Driver, error) {
	var err error

	v := kcpvpn_driver{
		localEndpoint: localEndpoint,
		connections:   make(map[string]*v1.Connection),
		spec:          new(specification),
	}

	err = envconfig.Process(specEnvPrefix, &v.spec)
	if err != nil {
		return nil, fmt.Errorf("error processing environment config for %s: %v", specEnvPrefix, err)
	}

	_, err = localEndpoint.Spec.GetBackendPort(v1.UDPPortConfig, int32(v.spec.NATTPort))
	if err != nil {
		return nil, fmt.Errorf("failed to get the UDP port configuration: %v", err)
	}

	return &v, nil
}

func (v *kcpvpn_driver) Init() error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if len(v.connections) != 0 {
		return fmt.Errorf("cannot initialize with existing connections: %+v", v.connections)
	}

	return nil
}

// ConnectToEndpoint establishes a connection to the given endpoint and returns a string
// representation of the IP address of the target endpoint.
func (v *kcpvpn_driver) ConnectToEndpoint(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {
	remoteEndpoint := &endpointInfo.Endpoint
	ip := endpointInfo.UseIP

	if v.localEndpoint.Spec.ClusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Will not connect to self")
		return "", nil
	}

	// parse remote addresses and allowed IPs
	remoteIP := net.ParseIP(ip)
	if remoteIP == nil {
		return "", fmt.Errorf("failed to parse remote IP %s", ip)
	}

	allowedIPs := parseSubnets(remoteEndpoint.Spec.Subnets)

	port, err := remoteEndpoint.Spec.GetBackendPort(v1.UDPPortConfig, int32(v.spec.NATTPort))
	if err != nil {
		klog.Warningf("Error parsing %q from remote endpoint %q - using port %dº instead: %v", v1.UDPPortConfig,
			remoteEndpoint.Spec.CableName, v.spec.NATTPort, err)
	}

	remotePort := int(port)

	klog.V(log.DEBUG).Infof("Connecting cluster %s endpoint %s:%d, AllowedIPs:%v",
		remoteEndpoint.Spec.ClusterID, remoteIP, remotePort, allowedIPs)
	v.mutex.Lock()
	defer v.mutex.Unlock()

	// delete or update old peers for ClusterID
	_, found := v.connections[remoteEndpoint.Spec.ClusterID]
	if found {
		delete(v.connections, remoteEndpoint.Spec.ClusterID)
	}

	// create connection, overwrite existing connection
	connection := v1.NewConnection(remoteEndpoint.Spec, ip, endpointInfo.UseNAT)
	connection.SetStatus(v1.Connecting, "Connection has been created but not yet started")
	klog.V(log.DEBUG).Infof("Adding connection for cluster %s, %v", remoteEndpoint.Spec.ClusterID, connection)
	v.connections[remoteEndpoint.Spec.ClusterID] = connection

	cable.RecordConnection(cableDriverName, &v.localEndpoint.Spec, &remoteEndpoint.Spec, string(v1.Connected), true)

	return ip, nil
}

// DisconnectFromEndpoint disconnects from the connection to the given endpoint.
func (v *kcpvpn_driver) DisconnectFromEndpoint(remoteEndpoint types.SubmarinerEndpoint) error {
	klog.V(log.DEBUG).Infof("Removing endpoint %v+", remoteEndpoint)

	if v.localEndpoint.Spec.ClusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Will not disconnect self")
		return nil
	}

	v.mutex.Lock()
	defer v.mutex.Unlock()

	delete(v.connections, remoteEndpoint.Spec.ClusterID)

	klog.V(log.DEBUG).Infof("Done removing endpoint for cluster %s", remoteEndpoint.Spec.ClusterID)
	cable.RecordDisconnected(cableDriverName, &v.localEndpoint.Spec, &remoteEndpoint.Spec)

	return nil
}

// GetConnections() returns an array of the existing connections, including status and endpoint info
func (v *kcpvpn_driver) GetConnections() ([]v1.Connection, error) {
	connections := make([]v1.Connection, 0)

	v.mutex.Lock()
	defer v.mutex.Unlock()

	for _, con := range v.connections {
		connections = append(connections, *con.DeepCopy())
	}

	return connections, nil
}

// GetActiveConnections returns an array of all the active connections
func (v *kcpvpn_driver) GetActiveConnections() ([]v1.Connection, error) {
	// force caller to skip duplicate handling
	return make([]v1.Connection, 0), nil
}

func (v *kcpvpn_driver) GetName() string {
	return cableDriverName
}

// parse CIDR string and skip errors
func parseSubnets(subnets []string) []net.IPNet {
	nets := make([]net.IPNet, 0, len(subnets))

	for _, sn := range subnets {
		_, cidr, err := net.ParseCIDR(sn)
		if err != nil {
			// this should not happen. Log and continue
			klog.Errorf("failed to parse subnet %s: %v", sn, err)
			continue
		}

		nets = append(nets, *cidr)
	}

	return nets
}
