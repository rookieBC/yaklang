package minimartian

import (
	"context"
	"net"
	"time"

	"github.com/yaklang/yaklang/common/netx"
	"github.com/yaklang/yaklang/common/utils"
)

const rawTunnelDialTimeout = 30 * time.Second

func (p *Proxy) dialRawTunnel(target, host, strongHostLocalAddr string) (net.Conn, error) {
	opts := []netx.DialXOption{
		netx.DialX_WithTimeout(rawTunnelDialTimeout),
		netx.DialX_WithEnableSystemProxyFromEnv(!p.disableSystemProxy),
		netx.DialX_WithDialer(p.dialer),
	}
	if proxies := p.selectProxiesForHost(host); len(proxies) > 0 {
		opts = append(opts,
			netx.DialX_WithProxy(proxies...),
			netx.DialX_WithForceProxy(true),
		)
	}
	if strongHostLocalAddr != "" {
		opts = append(opts, netx.DialX_WithStrongHostMode(strongHostLocalAddr))
	}
	return netx.DialX(target, opts...)
}

// handleRawTunnel applies tcpmitm's default behavior for an unknown protocol:
// preserve the sniffed bytes and transparently forward the TCP stream.
func (p *Proxy) handleRawTunnel(ctx context.Context, downstream net.Conn, host string, port int, strongHostLocalAddr string) error {
	target := utils.HostPort(host, port)
	upstream, err := p.dialRawTunnel(target, host, strongHostLocalAddr)
	if err != nil {
		return utils.Errorf("dial raw tunnel target %s failed: %s", target, err)
	}
	defer upstream.Close()

	return connectionFallback(ctx, downstream, upstream, false)
}
