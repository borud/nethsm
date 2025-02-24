.PHONY: test
.PHONY: slow-test
.PHONY: vet
.PHONY: staticcheck
.PHONY: gen-nethsm-rest-api
.PHONY: lint
.PHONY: clean

default: vet lint test

test:
	@echo "*** $@"
	@go test -timeout 2m ./...

slow-test:
	@echo "*** $@"
	@TEST_TAG=slowtest go test -v -timeout=5m . -run 'TestSession' session_test.go

vet:
	@echo "*** $@"
	@go vet ./...

staticcheck:
	@echo "*** $@"
	@staticcheck ./...

lint:
	@echo "*** $@"
	@revive ./...

gen-nethsm-rest-api:
	@echo "*** $@"
	docker run --rm -ti \
		-v "${PWD}:/local" \
		openapitools/openapi-generator-cli generate \
		-i https://nethsmdemo.nitrokey.com/api_docs/nethsm-api.yaml \
		-o /local/api \
		-g go \
		--package-name api \
		--additional-properties=enumClassPrefix=true,generateTests=false,apiTests=false,modelTests=false,apiDocs=false,modelDocs=false
	rm -rf api/{docs,test,.openapi-generator,api}
	rm -f api/{go.mod,go.sum,*.sh,.openapi-generator-ignore,README.md,.gitignore,.travis.yml}
	printf 'checks = [\n\t"all",\n\t"-ST1005",\n\t"-ST1000",\n\t"-SA4006"\n]\n' > api/staticcheck.conf
