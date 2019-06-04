FROM rust:latest

LABEL "com.github.actions.name"="Rust Action"
LABEL "com.github.actions.icon"="cpu"
LABEL "com.github.actions.color"="orange"

RUN rustup component add rustfmt

RUN cargo install --force cargo-fuzz afl honggfuzz

RUN apt-get update && \
	apt-get install -y cmake && \
	rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
