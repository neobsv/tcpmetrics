FROM golang:1.22 AS build

RUN mkdir /app
WORKDIR /app

COPY . .

RUN go get .
RUN go build -o tcpmetrics main.go
RUN chmod 555 tcpmetrics
RUN chmod 555 test1

FROM debian:bookworm-slim
COPY --from=build /app .

RUN useradd -u 1001 new_user
USER new_user

CMD ["bash"]
