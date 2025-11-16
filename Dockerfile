FROM golang:1.25-alpine
WORKDIR /app

# Copy the Go Modules manifests
COPY go.* ./

# Install remote debugger
RUN go install github.com/go-delve/delve/cmd/dlv@latest

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY . .

RUN go build

CMD ["./go-oidc-idp-example"]
