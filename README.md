# NIDS Backend

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Contributing](#contributing)

## Introduction

The NIDS Backend is a robust and scalable backend service designed to support the Network Intrusion Detection System (NIDS). It provides APIs and data processing capabilities to detect and respond to network threats in real-time.

## Features

- Real-time network traffic analysis
- Threat detection and alerting
- Scalable architecture
- RESTful API endpoints
- Comprehensive logging and monitoring

## Installation

To install the NIDS Backend, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/idris-adigun/nids-backend.git
   ```
2. Navigate to the project directory:
   ```bash
   cd nids-backend
   ```
3. Install dependencies:
   ```bash
   npm install
   ```

## Usage

To test the NIDS

```
cd nids
```

Run Python Script

```
python3 controller.py
```

## Configuration [WIP]

The NIDS Backend can be configured using environment variables. Create a `.env` file in the root directory and add the following variables:

```env
PORT=3000
DB_HOST=localhost
DB_USER=root
DB_PASS=password
DB_NAME=nids
```

## Contributing

We welcome contributions to the NIDS Backend project. To contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-branch
   ```
3. Make your changes and commit them:
   ```bash
   git commit -m "Description of changes"
   ```
4. Push to the branch:
   ```bash
   git push origin feature-branch
   ```
5. Create a pull request.
