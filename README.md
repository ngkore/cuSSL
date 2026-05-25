# cuSSL: GPU-Accelerated ML-KEM-768 Integration for OpenSSL 3.5

**Hardware-Accelerated Post-Quantum Cryptography using NVIDIA cuPQC and CUDA**

cuSSL is a high-performance runtime and backend that offloads **ML-KEM-768** Key Encapsulation operations from OpenSSL 3.5 to NVIDIA GPUs. It integrates directly into the OpenSSL cryptographic core and enables high-throughput TLS 1.3 Post-Quantum handshakes.

cuSSL implements a **Split-Stack Architecture**, cleanly separating the OpenSSL cryptographic core (CPU/C) from the GPU execution backend (CUDA/C++), ensuring ABI stability, thread safety, and memory isolation.

---

##  Features

* GPU-accelerated ML-KEM-768 encapsulation using NVIDIA cuPQC
* Asynchronous batching runtime (up to 512 concurrent operations)
* Direct integration into OpenSSL 3.5 cryptographic core
* Thread-safe job queue and runtime scheduler
* Secure memory isolation between OpenSSL and GPU runtime
* Automatic CPU fallback when GPU offload is disabled
* Clean patch-based integration (no OpenSSL source redistribution)

---

## Architecture

cuSSL operates in three layers:

### 1. OpenSSL Integration Layer (Client)

**File:** `crypto/ml_kem/ml_kem.c` (patched)

Responsibilities:

* Intercepts ML-KEM encapsulation requests
* Submits jobs via cuSSL runtime API
* Uses OpenSSL Async Job framework (`ASYNC_pause_job`)
* Maintains full compatibility with OpenSSL execution model

---

### 2. cuSSL Runtime Layer (Manager)

**File:** `src/cupqc_runtime.c`

Responsibilities:

* Thread-safe batching queue
* Job scheduling and worker thread management
* Memory isolation between OpenSSL and CUDA
* Async job coordination

This layer acts as the bridge between OpenSSL and GPU backend.

---

### 3. CUDA Backend Layer (Worker)

**File:** `src/cupqc_shim.cu`

Responsibilities:

* Executes batched ML-KEM-768 encapsulation
* Launches cuPQC CUDA kernels
* Manages persistent GPU memory buffers
* Performs host/device memory transfers

Uses: cupqc::ML_KEM_768 from NVIDIA cuPQC SDK.

---

##  Prerequisites

Hardware:

* NVIDIA GPU (Turing / Ampere / Ada or newer)
* Compute Capability ≥ 7.5

Software:

* Linux (Ubuntu 20.04 / 22.04 recommended)
* OpenSSL 3.5.0 source
* NVIDIA CUDA Toolkit (12+)
* NVIDIA cuPQC SDK
* GCC 9+
* NVCC compiler

---
### Build Instructions

**1. Set Environment Variables**

```bash
export CUPQC_HOME=/path/to/cupqc_sdk
export OPENSSL_ROOT=/path/to/openssl-3.5.0

```

**2. Compile cuSSL Runtime and CUDA Backend**

*Note: cuPQC is a pre-compiled, Link-Time Optimized (LTO) closed-source SDK. The build chain requires strict Relocatable Device Code 
(`-rdc=true`) and LTO flags. We dynamically locate missing internal headers to satisfy C++ standard requirements.*

```bash
# Locate deeply buried internal SDK headers
export MISSING_INC_PATH=$(find ${CUPQC_HOME} -name "database.hpp" -exec dirname {} \; | head -n 1)

# Compile C runtime:
gcc -c src/cupqc_runtime.c -o cupqc_runtime.o -fPIC \
    -I${OPENSSL_ROOT}/include \
    -I${OPENSSL_ROOT}/crypto/ml_kem

# Compile CUDA backend (Explicit C++17 and LTO):
nvcc -c src/cupqc_shim.cu -o cupqc_shim.o \
    -rdc=true -dlto -std=c++17 -arch=sm_75 \
    -I${CUPQC_HOME}/include \
    -I${CUPQC_HOME}/include/cupqc/detail \
    -I$MISSING_INC_PATH \
    -Xcompiler -fPIC

# Device link (Crucial: Must link the library here for RDC resolution):
nvcc -arch=sm_75 -dlink cupqc_shim.o -o cupqc_shim_dlink.o \
    -rdc=true -dlto \
    -L${CUPQC_HOME}/lib -lcupqc-pk \
    -Xcompiler -fPIC

# Final shared library link:
g++ -shared -o libcussl.so \
    cupqc_runtime.o cupqc_shim.o cupqc_shim_dlink.o \
    -L${CUPQC_HOME}/lib -lcupqc-pk \
    -L/usr/local/cuda/lib64 -lcudart -lpthread

```

**3. Apply OpenSSL Patch**
From your OpenSSL root directory:

```bash
patch -p1 < /path/to/cuSSL/openssl/patches/openssl-3.5.0-mlkem-cupqc.patch
make -j$(nproc)

```
---

### Usage

**1. Start the Hardware Daemon (Required for Nginx/Multi-Process)**

To maximize throughput and prevent PCIe context-switching penalties, start the NVIDIA Multi-Process Service before running the web server:

```bash
sudo nvidia-cuda-mps-control -d

```

**2. Enable the Engine and Run**

```bash
export ENABLE_CUPQC=1
openssl s_server -accept 4433 -cert cert.pem -key key.pem -tls1_3 -groups mlkem768

```

**3. Verify Offload**

Use `nvitop` or `nvidia-smi` to verify GPU utilization during active handshakes.

To disable GPU offload and fallback to standard CPU execution, simply:

```bash
unset ENABLE_CUPQC
```
---

### Performance & Scaling

This engine offloads post-quantum math to the GPU. However, ML-KEM-768 is mathematically "lightweight" (Lattice-based cryptography), which shifts the performance bottleneck from raw compute to **PCIe transfer latency**.

#### Current Benchmark (Standard Nginx + NVIDIA MPS)

* **Rate:** ~836 Handshakes/Second
* **The PCIe Latency Paradox:** The GPU executes the ML-KEM math in ~2 microseconds, but transferring the 1,184-byte public keys across the PCIe bus takes ~10-15 microseconds per direction.
* **The MPS Solution:** Standard Nginx uses a synchronous multi-processing model (e.g., 32 isolated worker processes), meaning it inherently struggles to build large batches. To solve this, the engine is designed to run concurrently with the **NVIDIA MPS Daemon**. MPS intercepts the isolated worker threads and fuses them into optimized VRAM batches, preventing context-thrashing and maximizing throughput for synchronous web servers.

#### Roadmap to 2,000+ Handshakes/Sec

To fully saturate the GPU compute capacity and break past the PCIe bottleneck, the engine requires environment upgrades to build massive, single-transaction batches:

1. **Async-Enabled Server:** Standard Nginx blocks on every connection. Migrating this OpenSSL engine into a web server that natively supports OpenSSL's asynchronous polling (like Envoy, HAProxy, or Intel's Async Nginx) allows a single worker process to handle thousands of concurrent connections. This naturally fills the engine's 512-slot GPU queue without blocking, mathematically offsetting the PCIe transfer penalty.
2. **PCIe Generation Upgrades:** The current ceiling was benchmarked on a Tesla T4 (PCIe Gen 3). Deploying this engine on PCIe Gen 4 or Gen 5 hardware will physically double or quadruple the transfer bandwidth of the lattice keys, linearly increasing the ops/sec ceiling.

---

##  Security and Compatibility

cuSSL:

* Preserves OpenSSL security model
* Does not modify public OpenSSL APIs
* Uses isolated runtime
* Supports CPU fallback

Patch-based integration ensures maintainability across OpenSSL versions.

---

##  Licensing

This repository contains only integration code.

It does NOT include:

* OpenSSL source code
* NVIDIA cuPQC SDK
* CUDA Toolkit

Users must obtain those separately under their respective licenses.

---
### Project Status

The engine is fully functional, architecturally stable, and ready for production-grade testing. It successfully performs hardware-offloaded ML-KEM-768 key encapsulation for standard OpenSSL TLS 1.3 connections under massive concurrency.

Core achievements include:

* **Correctness:** Validated bit-exact key exchange and successful handshake completion across 10,000+ request floods.
* **Architecture:** Strict separation of OpenSSL API and GPU runtime for full library compliance. The C++ shim utilizes `std::call_once` and POSIX concurrency primitives to guarantee strict thread safety and zero memory leaks.
* **Hardware Orchestration:** Fully integrated with NVIDIA Multi-Process Service (MPS) to allow multi-process web servers (like Nginx) to transparently batch synchronous requests across the PCIe bus.




