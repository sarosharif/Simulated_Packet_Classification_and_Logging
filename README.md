# Simulated Packet Classification and Logging

This project is designed for simulating packet classification and logging. It consists of a **collector** and three binaries (**b1**, **b2**, **b3**), which send traffic read from a **PCAP** file in zero-copy mode, classify the traffic, and send it to the collector.

## Project Structure

- **collector**: The central component that receives classified traffic.
- **b1, b2, b3**: Binaries that send traffic, classify it, and send the results to the collector.
- **Dockerfile**: Builds the Docker image that compiles the project.
- **Meson build system**: Used for building the project within Docker.

## Requirements

- Docker
- Meson build system
- PCAP file for traffic simulation

## Setup and Running

Follow these steps to build and run the project:

### 1. Clone the repository and build docker 

Clone this repository to your local machine and build docker:

```bash
git clone https://github.com/sarosharif/Simulated_Packet_Classification_and_Logging.git
cd Simulated_Packet_Classification_and_Logging
docker build -t packet-classification .
docker run -it --rm packet-classification /bin/bash
```

### 2. Running 
You can run the projecy in the following way:

```bash
cd build
./collector
./b1 ../test_captures/anghami_16_mb_flow.pcap
./b2 ../test_captures/wificapture.pcap
./b3 ../test_captures/postman_echo_http.pcap
```

for this to run, collector must be running before you run b1,b2,b3. If you'll give wrong inputs to the binary it'll crash. That case is not handled. 
collector will generate three different logs collector_b1.log, collector_b2.log, collector_b3.log. 
b1, b2, b3 can handle one capture only after that you'll need to run it again if you wish. 
You can run it with capture of your own choice. 

## Limitations 

1. ipv6 is not handled 
2. Classification logic is simple pattern matching, you can add more things to domain_to_app.ini
3. Packet is not parsed beyond ip header so no sni based matching 
4. If te collector log rollover is not handled, it'll keep growing as long as collector is running 
5. Flow state is not maintained, meaning if the flow closes and opens again with same ip, port and protocol for a different app classification will be wrong. 
6. If capture or pkts are corrupted, that is not handled 
7. Any protocol other than udp and tcp is not handled 

