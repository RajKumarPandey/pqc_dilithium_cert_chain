# PQC Certificate Chain using Placeholder (Dilithium)

This project demonstrates how to simulate a certificate chain (Root, Intermediate, User) using placeholder EC keys in place of actual Dilithium keys.

## 🧪 Structure

- `src/`: Core utility functions to generate and build X.509 certificate chains.
- `tests/`: Unit tests validating structure and chain building.
- `docs/`: Reserved for documentation.
- `requirements.txt`: Lists required Python dependencies.

## 🚀 How to Run

```bash
pip install -r requirements.txt
python -m unittest discover tests
```

> Note: Dilithium key generation is simulated using EC keys. Replace with real PQC implementations as needed.
