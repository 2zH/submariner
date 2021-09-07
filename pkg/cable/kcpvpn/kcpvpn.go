package kcpvpn

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/submariner-io/admiral/pkg/log"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	"github.com/submariner-io/submariner/pkg/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog"

	pb "github.com/submariner-io/submariner/pkg/cable/kcpvpn/controller"
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

	controlConn   *grpc.ClientConn
	controlClient pb.KCPVPNCtlClient
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

	err = envconfig.Process(specEnvPrefix, v.spec)
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

	if err := v.runServer(v.spec.NATTPort); err != nil {
		return fmt.Errorf("error starting kcpvpn server: %v", err)
	}

	// Wait up to 5s for the control socket
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	for i := 0; i < 5; i++ {
		conn, err := grpc.Dial("localhost:2000", opts...)
		if err == nil {
			v.controlConn = conn
			v.controlClient = pb.NewKCPVPNCtlClient(conn)
			break
		}

		time.Sleep(1 * time.Second)
	}

	if v.controlClient == nil {
		return fmt.Errorf("failed to connect to controller")
	}

	klog.Info("kcpvpn control service connected")

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
	connectionMode := v.calculateOperationMode(&remoteEndpoint.Spec)

	klog.Infof("Connecting to cluster %s endpoint %s:%d in %s mode, AllowedIPs:%v ",
		remoteEndpoint.Spec.ClusterID, remoteIP, remotePort, connectionMode, allowedIPs)
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if connectionMode == operationModeClient {
		_, err := v.controlClient.ConnectToCluster(context.Background(), &pb.ConnectToClusterRequest{
			ClusterId: v.localEndpoint.Spec.ClusterID,
			Subnets:   convertToPBSubnets(allowedIPs),
			IpAddress: remoteIP.String(),
			Port:      int32(remotePort),
		})
		if err != nil {
			s := status.Convert(err)
			if s.Code() == codes.AlreadyExists {
				return ip, nil
			}
			klog.Warningf("failed to call ConnectToCluster: %v", err)
			return "", err
		}
	} else if connectionMode == operationModeServer {
		_, err := v.controlClient.AllowConnectionFromCluster(context.Background(), &pb.AllowConnectionFromClusterRequest{
			ClusterId: remoteEndpoint.Spec.ClusterID,
			Subnets:   convertToPBSubnets(allowedIPs),
		})
		if err != nil {
			klog.Warningf("failed to call AllowConnectionFromCluster: %v", err)
			return "", err
		}
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
	if v.localEndpoint.Spec.ClusterID == remoteEndpoint.Spec.ClusterID {
		klog.V(log.DEBUG).Infof("Will not disconnect self")
		return nil
	}

	klog.Infof("Removing connection to %v+", remoteEndpoint)

	v.mutex.Lock()
	defer v.mutex.Unlock()

	_, err := v.controlClient.DisconnectFromCluster(context.Background(), &pb.DisconnectFromClusterRequest{ClusterId: remoteEndpoint.Spec.ClusterID})
	if err != nil {
		klog.Warningf("failed to call DisconnectFromCluster: %v", err)
	}
	delete(v.connections, remoteEndpoint.Spec.ClusterID)

	klog.V(log.DEBUG).Infof("Done removing endpoint for cluster %s", remoteEndpoint.Spec.ClusterID)
	cable.RecordDisconnected(cableDriverName, &v.localEndpoint.Spec, &remoteEndpoint.Spec)

	return nil
}

func pbStatusToSubStatus(s pb.ConnectionStatus) v1.ConnectionStatus {
	switch s {
	case pb.ConnectionStatus_Connected:
		return v1.Connected
	case pb.ConnectionStatus_Connecting:
		return v1.Connecting
	}
	return v1.ConnectionError
}

func (v *kcpvpn_driver) refreshConnectionStatus() error {
	resp, err := v.controlClient.GetConnections(context.Background(), &pb.GetConnectionsRequest{})
	if err != nil {
		return err
	}

	v.mutex.Lock()
	defer v.mutex.Unlock()

	cable.RecordNoConnections()

	for i, c := range resp.Connections {
		klog.Infof("Conn[%d]: %s (%v) rx: %d tx: %d", i, c.ClusterId, c.Status, c.RecvBytes, c.SentBytes)
		local_conn, found := v.connections[c.ClusterId]
		if !found {
			klog.Warningf("connection to %s not found in local state", c.ClusterId)
			continue
		}
		local_conn.Status = pbStatusToSubStatus(c.Status)

		cable.RecordConnection(cableDriverName, &v.localEndpoint.Spec, &local_conn.Endpoint, string(local_conn.Status), false)
		cable.RecordRxBytes(cableDriverName, &v.localEndpoint.Spec, &local_conn.Endpoint, int(c.RecvBytes))
		cable.RecordTxBytes(cableDriverName, &v.localEndpoint.Spec, &local_conn.Endpoint, int(c.SentBytes))
	}

	return nil
}

// GetConnections() returns an array of the existing connections, including status and endpoint info
func (v *kcpvpn_driver) GetConnections() ([]v1.Connection, error) {
	if err := v.refreshConnectionStatus(); err != nil {
		return []v1.Connection{}, err
	}

	return v.GetActiveConnections()
}

// GetActiveConnections returns an array of all the active connections
func (v *kcpvpn_driver) GetActiveConnections() ([]v1.Connection, error) {
	connections := make([]v1.Connection, 0)

	v.mutex.Lock()
	defer v.mutex.Unlock()

	for _, con := range v.connections {
		connections = append(connections, *con.DeepCopy())
	}

	return connections, nil
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

func convertToPBSubnets(subnets []net.IPNet) []*pb.Subnet {
	nets := make([]*pb.Subnet, 0, len(subnets))

	for _, sn := range subnets {
		ones, _ := sn.Mask.Size()
		nets = append(nets, &pb.Subnet{
			Ip:   sn.IP.String(),
			Mask: uint32(ones),
		})
	}

	return nets
}

func (v *kcpvpn_driver) runServer(listenPort int) error {
	klog.Info("Starting kcpvpn server")

	args := []string{
		"server",
		"--ip", "0.0.0.0",
		"--port", strconv.Itoa(listenPort),
		"--kcp-mode", "fast3",
		"--vni-mode", "tun",
		"--local-ip", "10.188.0.0",
		"--assignable-ips", "10.188.0.0/16",
		"--secret", v.spec.PSK,
	}

	cmd := exec.Command("/usr/local/bin/kcpvpn", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	var outputFile *os.File

	if v.spec.LogFile != "" {
		out, err := os.OpenFile(v.spec.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file %s: %v", v.spec.LogFile, err)
		}

		cmd.Stdout = out
		cmd.Stderr = out
		outputFile = out
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}

	if err := cmd.Start(); err != nil {
		// Note - Close handles nil receiver
		outputFile.Close()
		return fmt.Errorf("error starting the kcpvpn process with args %v: %v", args, err)
	}

	go func() {
		defer outputFile.Close()
		klog.Fatalf("kcpvpn server exited: %v", cmd.Wait())
	}()

	return nil
}

func (v *kcpvpn_driver) runClientConnectTo(localClusterID string, psk string, remoteIP net.IP, remotePort int) error {
	klog.Info("Starting kcpvpn client")

	args := []string{
		"client",
		"--client-id", localClusterID,
		"--ip", remoteIP.String(),
		"--port", strconv.Itoa(remotePort),
		"--kcp-mode", "fast3",
		"--secret", psk,
	}

	cmd := exec.Command("/usr/local/bin/kcpvpn", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	var outputFile *os.File

	if v.spec.LogFile != "" {
		out, err := os.OpenFile(v.spec.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file %s: %v", v.spec.LogFile, err)
		}

		cmd.Stdout = out
		cmd.Stderr = out
		outputFile = out
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}

	if err := cmd.Start(); err != nil {
		// Note - Close handles nil receiver
		outputFile.Close()
		return fmt.Errorf("error starting the kcpvpn process with args %v: %v", args, err)
	}

	go func() {
		defer outputFile.Close()
		klog.Fatalf("kcpvpn client exited: %v", cmd.Wait())
	}()

	return nil
}
