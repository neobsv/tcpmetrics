all: build test

build:
	go build -o tcpmetrics main.go
	chmod 550 tcpmetrics

test:
	cd fparser ; go test -v ; cd ..
	cd cscanner ; go test -v ; cd ..

run:
	go build -o tcpmetrics main.go
	chmod 550 tcpmetrics
	./tcpmetrics -filename=test1

clean:
	go clean