# Shepherd Serial Monitor

A specialized serial monitor and analysis tool for Shepherd targets. It handles real-time data monitoring, matrix calculations, and XML data management.

## Configuration

To adjust the serial connection settings, edit `concurrent_monitor.py`:

  * **Change Port:** Modify the `PORT` variable.
  * **Change Baud Rate:** Modify the `BAUD` variable.

## Usage

You can run the application in two modes via `main.py`:

### 1\. Live Monitor Mode

Connects to the serial port defined in `concurrent_monitor.py`.

```bash
python main.py
```

### 2\. File Analysis Mode

Loads and analyzes a previously saved XML dataset.

```bash
python main.py raw_data/my_data.xml
```

## Core Logic (data\_storage.py)

The main processing occurs in `data_storage.py` and includes:

  * **Matrix Calculations:** Computation logic for incoming data.
  * **Visualization:** Data display and rendering.
  * **I/O:** Import and export functionality for XML files.
  * **Filtering:** Data filter functions.