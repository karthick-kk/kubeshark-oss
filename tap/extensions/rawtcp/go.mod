module github.com/karthick-kk/kubeshark-oss/tap/extensions/rawtcp

go 1.17

require github.com/karthick-kk/kubeshark-oss/tap/api v0.0.0

require github.com/karthick-kk/kubeshark-oss/tap/dbgctl v0.0.0 // indirect

replace github.com/karthick-kk/kubeshark-oss/tap/api v0.0.0 => ../../api

replace github.com/karthick-kk/kubeshark-oss/tap/dbgctl v0.0.0 => ../../dbgctl
