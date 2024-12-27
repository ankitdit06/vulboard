# Stage 1: Build the application
FROM golang:1.23 AS builder

# Set environment variables for Go build
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /app

# Copy and download dependency using go mod
COPY config.json go.mod go.sum ./
RUN  go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o /vulboard .

# Stage 2: Create a minimal final image
FROM gcr.io/distroless/static:nonroot

# Copy the binary from the builder
COPY --from=builder /vulboard /vulboard
COPY --from=builder /app/config.json .

# Set the entrypoint to the application binary
ENTRYPOINT ["/vulboard"]

# Expose the application port
EXPOSE 8080
