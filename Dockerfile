FROM rust:latest AS build

WORKDIR /usr/src/app
COPY . .

RUN cargo build --release

FROM gcr.io/distroless/cc AS final
WORKDIR /usr/src/app

# Copy the built binary from the previous stage
COPY --from=build /usr/src/app/target/release/namecheap-ddns-updater .
CMD ["./namecheap-ddns-updater"]