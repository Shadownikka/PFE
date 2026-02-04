# NetCut AI - Project Structure Overview

## File Organization

The project has been successfully refactored into a modular architecture with clear separation of concerns:

### **Core Files**

#### 1. **tool.py** (12 KB)
**Low-level networking and bandwidth control**

Contains:
- `Config` class - System configuration parameters
- Utility functions - `has_root()`, `get_gateway_ip()`, `enable_ip_forwarding()`, etc.
- `ARPSpoofer` class - Performs MITM attacks via ARP spoofing
- `TrafficMonitor` class - Monitors bandwidth using iptables
- `BandwidthController` class - Applies traffic control limits using TC

**Key Features:**
- No user interaction
- Pure networking operations
- Can be imported and used independently
- Thread-safe with locks for concurrent operations

---

#### 2. **ai.py** (19 KB)
**Intelligent bandwidth management and user interface**

Contains:
- `IntelligentController` class - Wraps BandwidthController with smart algorithms
- `NetCutAI` class - Main system orchestrator
- Auto-balancing algorithm - Detects and limits bandwidth hogs
- Interactive menu system - Manual control interface

**Key Features:**
- High-level bandwidth management
- Automatic decision-making algorithms
- User-friendly CLI interface
- Signal handlers for graceful shutdown

---

#### 3. **NetCut.py** (2.7 KB)
**Main entry point and orchestrator**

Contains:
- `main()` function - Program startup and mode selection
- Mode selection logic - Automatic vs Manual + AI
- Import statements - Combines tool and AI modules

**Key Features:**
- Clean, minimal startup code
- Mode selection (Automatic/Manual)
- Single entry point for the application

---

### **Supporting Files**

- **README.md** (8.0 KB) - Comprehensive documentation
- **Setup.py** - Installation script
- **Depandance.txt** - Dependency list
- **requirements.txt** - Python package dependencies

---

## Module Hierarchy

```
NetCut.py (Entry Point)
    ↓
Imports: ai.py
    ↓
ai.py (AI Engine)
    ├─ Imports: tool.py
    ├─ Contains: IntelligentController, NetCutAI
    └─ Uses: BandwidthController from tool.py
    ↓
tool.py (Core Tool)
    ├─ Contains: ARPSpoofer, TrafficMonitor, BandwidthController
    ├─ Uses: scapy, iptables, tc commands
    └─ Dependencies: External system utilities
```

---

## Import Chain

### **tool.py**
- No imports from other project files
- External deps: `scapy`, `netifaces`, `termcolor`, `subprocess`, `threading`

### **ai.py**
```python
from tool import (
    Config, has_root, get_gateway_ip, get_default_interface, 
    get_subnet_cidr, enable_ip_forwarding, discover_clients,
    TrafficMonitor, BandwidthController
)
```

### **NetCut.py**
```python
from ai import NetCutAI, Config
```

---

## Separation of Concerns

### **tool.py** - The Toolbox
- **Responsibility**: Low-level network operations
- **Abstraction Level**: System-level (iptables, tc, ARP)
- **Coupling**: Only external libraries
- **Testing**: Can be unit tested independently

### **ai.py** - The Brain
- **Responsibility**: Decision-making and management
- **Abstraction Level**: Application-level (bandwidth strategy)
- **Coupling**: tool.py for operations
- **Testing**: Can be tested with mock Tool objects

### **NetCut.py** - The Interface
- **Responsibility**: User interaction and flow
- **Abstraction Level**: User interface
- **Coupling**: ai.py for engine
- **Testing**: Integration testing

---

## Data Flow

```
User Input (NetCut.py)
    ↓
Mode Selection
    ↓
NetCutAI.start_monitoring()
    ↓
↙─────────────────────┬─────────────────────┐
│                     │                     │
ARP Spoofing    Traffic Monitoring    Display Stats
(tool.py)       (tool.py)             (ai.py)
│                │                      │
└─────────────────────┬─────────────────┘
                      ↓
            IntelligentController
            (ai.py)
            Auto-balancing
            Limit Application
                      ↓
        Apply/Remove Limits
        (BandwidthController)
```

---

## Configuration Management

All system configuration is centralized in `tool.py`:

```python
class Config:
    MONITOR_INTERVAL = 3
    HISTORY_LENGTH = 20
    MAX_SINGLE_DEVICE_PERCENT = 40
    MIN_GUARANTEED_KBPS = 256
    AUTO_LIMIT_ENABLED = True
    BANDWIDTH_ABUSE_THRESHOLD = 5000
    TOTAL_BANDWIDTH_KBPS = None
    STATE_FILE = "/tmp/netcut_ai_state.json"
```

This Config class is imported and used by `ai.py` for all behavioral parameters.

---

## Execution Flow

### **Automatic Mode**
```
Start → Scan → Monitor → Auto-Balance Loop → Display → Shutdown
```

### **Manual Mode**
```
Start → Scan → Monitor → Menu → Manual Action → Continue/Stop
```

---

## File Sizes & Metrics

| File | Size | Lines | Purpose |
|------|------|-------|---------|
| tool.py | 12 KB | ~400 | Core networking |
| ai.py | 19 KB | ~550 | Intelligence & UI |
| NetCut.py | 2.7 KB | ~70 | Entry point |
| README.md | 8.0 KB | ~300 | Documentation |
| **Total** | **41.7 KB** | **~1320** | Complete system |

---

## Code Quality Improvements

✅ **Modularity**: Each file has a single responsibility
✅ **Testability**: Core logic can be tested independently
✅ **Maintainability**: Clear separation makes updates easier
✅ **Reusability**: tool.py can be used independently
✅ **Scalability**: Easy to add new features without affecting existing code

---

## Future Extensibility

The modular structure enables easy addition of:

1. **New Interfaces**
   - Web UI (import NetCutAI from ai.py)
   - REST API (import functions from tool.py)
   - Mobile app (same imports)

2. **New Algorithms**
   - Add methods to IntelligentController in ai.py
   - Keep tool.py untouched

3. **New Monitoring Features**
   - Extend TrafficMonitor in tool.py
   - Add visualization to ai.py

4. **New Bandwidth Strategies**
   - Create new controller subclass in ai.py
   - Use existing BandwidthController from tool.py

---

**Last Updated**: January 21, 2026
**Refactoring Version**: 1.0
