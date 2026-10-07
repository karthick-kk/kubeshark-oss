package servicemap

import (
	tapApi "github.com/karthick-kk/kubeshark-oss/tap/api"
)

type ServiceMapStatus struct {
	Status                string `json:"status"`
	EntriesProcessedCount int    `json:"entriesProcessedCount"`
	NodeCount             int    `json:"nodeCount"`
	EdgeCount             int    `json:"edgeCount"`
}

type ServiceMapResponse struct {
	Status ServiceMapStatus `json:"status"`
	Nodes  []ServiceMapNode `json:"nodes"`
	Edges  []ServiceMapEdge `json:"edges"`
}

type ServiceMapNode struct {
	Id       int         `json:"id"`
	Name     string      `json:"name"`
	Entry    *tapApi.TCP `json:"entry"`
	Count    int         `json:"count"`
	Resolved bool        `json:"resolved"`
}

type ServiceMapEdge struct {
	Source      ServiceMapNode   `json:"source"`
	Destination ServiceMapNode   `json:"destination"`
	Count       int              `json:"count"`
	Protocol    *tapApi.Protocol `json:"protocol"`
	// AvgLatency is the mean round-trip time of the entries on this edge, in
	// milliseconds. Zero for edges whose dissectors do not report a latency.
	AvgLatency int64 `json:"avgLatency"`
	// RequestBytes / ResponseBytes are the cumulative bytes sent on (and
	// returned over) the edge across all its entries.
	RequestBytes  int `json:"requestBytes"`
	ResponseBytes int `json:"responseBytes"`
}
