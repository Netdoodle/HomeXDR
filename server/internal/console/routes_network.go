package console

// routesNetwork registers the network feature's routes.
func (h *Handler) routesNetwork(viewer, analyst, admin string) {}

// netflowStats is the NetFlow section of the integrations page.
func (h *Handler) netflowStats() map[string]any {
	f := h.c.Flow
	return map[string]any{
		"enabled": h.c.Cfg.NetFlowAddr != "", "listening": f.Listening.Load(), "addr": f.Addr.Load(),
		"packets": f.Packets.Load(), "records": f.Records.Load(), "dropped": f.Dropped.Load(),
		"refused": f.Refused.Load(), "malformed": f.Malformed.Load(), "waiting": f.Waiting.Load(),
		"discarded": f.Discarded.Load(), "failed": f.Failed.Load(), "exporters": f.Exporters(),
	}
}
