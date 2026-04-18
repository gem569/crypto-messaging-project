# Cryptographic Messaging Simulation

This project implements and analyses Diffie–Hellman key exchange, including real-world attack scenarios and protocol fixes.

## Features

- Diffie–Hellman key exchange
- Symmetric encryption (XOR-based for demonstration)
- Man-in-the-Middle (MITM) attack simulation
- Secure protocol variant with attack detection

## Project Structure

- `core/` – cryptographic primitives
- `attacks/` – adversarial models (MITM)
- `secure/` – improved protocol design
- `demos/` – runnable experiments

## How to Run

From the project root:

```bash
python -m demos.run_dh_demo
python -m demos.run_mitm_demo
python -m demos.run_secure_demo