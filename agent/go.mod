module github.com/Netdoodle/homexdr/agent

go 1.26.0

require github.com/Netdoodle/homexdr/shared v0.0.0

require golang.org/x/sys v0.49.0

require github.com/cilium/ebpf v0.22.0

replace github.com/Netdoodle/homexdr/shared => ../shared
