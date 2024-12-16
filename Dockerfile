# Use an official Ubuntu as the base image
FROM ubuntu:20.04

# Set environment variables to prevent some prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies: ZeroMQ, Git, Meson, Ninja, build-essential
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    pkg-config \
    libzmq3-dev \
    meson \
    ninja-build \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory to /app
WORKDIR /app

# Copy the entire project into the container
COPY . /app

# Build the project using Meson and Ninja
RUN meson setup build && \
    ninja -C build

CMD ["tail -f /dev/null"]