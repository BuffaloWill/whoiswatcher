.phony: stest
stest:
	go build -o whoiswatcher cmd/whoiswatcher/main.go
	echo fidelity.com | ./whoiswatcher -e	-w .watchlist.yaml			# hit
	echo everettcc.edu | ./whoiswatcher -e -w .watchlist.yaml			# hit
	echo youtube.com | ./whoiswatcher -e -w .watchlist.yaml			# hit
	echo bankofamerica.com | ./whoiswatcher -e -w .watchlist.yaml		# hit
	echo paypal.com | ./whoiswatcher -e -w .watchlist.yaml  			# miss
	echo tesla.com | ./whoiswatcher -e -w .watchlist.yaml 			# miss

.phony: test
test:
	go build -o whoiswatcher cmd/whoiswatcher/main.go
	echo fidelity.com | ./whoiswatcher
	echo google.com | ./whoiswatcher
#	./whoiswatcher -f tests/domain_list.txt

.phony: testv
testv:
	go build -o whoiswatcher cmd/whoiswatcher/main.go
	./whoiswatcher -f tests/domain_list.txt -v

.phony: block
block:
	go build -o whoiswatcher cmd/whoiswatcher/main.go
	./whoiswatcher -f tests/sensitive.txt -e

.phony: blockv
blockv:
	go build -o whoiswatcher cmd/whoiswatcher/main.go
	./whoiswatcher -f tests/sensitive.txt -v -w .watchlist.yaml

.phony: nrd
nrd:
	go build -o whoiswatcher cmd/whoiswatcher/main.go
	shuf -n 100 tests/03132024-nrd.txt | tee tests/03132024-nrd-1k.txt
	time ./whoiswatcher -f tests/03132024-nrd-1k.txt -w .watchlist.yaml -v

.phony: z
z:
	go build -o whoiswatcher cmd/whoiswatcher/main.go
	echo llbean.com | ./whoiswatcher -w .watchlist.yaml

.phony: build
build:
	go build -o whoiswatcher cmd/whoiswatcher/main.go

.phony: jsoni
jsoni:
	go build -o whoiswatcher cmd/whoiswatcher/main.go
	echo fidelity.com | ./whoiswatcher -v | tee tests/many-tests.json
	echo fidelity.com | ./whoiswatcher -j tests/single-test.json -w .watchlist.yaml
	#./whoiswatcher -f tests/short_domain_list.txt -v | tee tests/many-lines.json
	echo fidelity.com | ./whoiswatcher -j tests/many-lines.json -w .watchlist.yaml
	echo brenau.edu | ./whoiswatcher -j tests/tenthousand-domains.json -w .watchlist.yaml