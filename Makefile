.phony: stest
stest:
	go build -o whoiswatcher cmd/whoiswatcher/main.go
	echo fidelity.com | ./whoiswatcher -e	-w .watchlist.yaml			# hit
	echo youtube.com | ./whoiswatcher -e -w .watchlist.yaml			# hit
	echo bankofamerica.com | ./whoiswatcher -e -w .watchlist.yaml		# hit
	echo paypal.com | ./whoiswatcher -e -w .watchlist.yaml -s 1 		# miss
	echo tesla.com | ./whoiswatcher -e -w .watchlist.yaml -s 1 			# miss

.phony: test
test:
	go build -o whoiswatcher cmd/whoiswatcher/main.go
	echo fidelity.com | ./whoiswatcher
	echo google.com | ./whoiswatcher

.phony: testv
testv:
	go build -o whoiswatcher cmd/whoiswatcher/main.go
	./whoiswatcher -f tests/domain_list.txt -v

.phony: nrd
nrd:
	go build -o whoiswatcher cmd/whoiswatcher/main.go
	shuf -n 100 tests/03132024-nrd.txt | tee tests/03132024-nrd-1k.txt
	time ./whoiswatcher -f tests/03132024-nrd-1k.txt -w .watchlist.yaml -v

.phony: build
build:
	go build -o whoiswatcher cmd/whoiswatcher/main.go

.phony: buildz
buildz:
	GOARCH=amd64 GOOS=linux go build -o builds/whoiswatcher-v1.0.0-amd64 cmd/whoiswatcher/main.go