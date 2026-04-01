module github.com/chelof100/acp-framework/compliance/adversarial

go 1.22.0

require (
	github.com/chelof100/acp-framework/acp-go v0.0.0-00010101000000-000000000000
	github.com/redis/go-redis/v9 v9.7.0
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
)

replace github.com/chelof100/acp-framework/acp-go => ../../impl/go
