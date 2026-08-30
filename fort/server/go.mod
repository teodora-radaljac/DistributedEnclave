module github.com/danko-miladinovic/fort/server

go 1.22

require (
	github.com/danko-miladinovic/fort/atls v0.0.0
	github.com/google/go-sev-guest v0.14.2-0.20251119154202-af1c107a648f
	google.golang.org/protobuf v1.33.0
)

require (
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/virtee/sev-snp-measure-go v0.0.0-20260408174629-fd0cc4c95d62 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
)

replace github.com/danko-miladinovic/fort/atls => ../atls
