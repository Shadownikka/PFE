# NetMind - Project Structure Overview

## File Organization

The project has been successfully refactored into a modular architecture with clear separation of concerns:

### **Core Files**

#### 1. **tool.py** (18.5 KB, ~619 lines)
**Low-level networking and bandwidth control**

Contains:
- `Config` class - System configuration parameters
- Utility functions - `has_root()`, `get_gateway_ip()`, `enable_ip_forwarding()`, etc.
- `ARPSpoofer` class - Performs MITM attacks via ARP spoofing
- `TrafficMonitor` class - Monitors bandwidth using iptables byte counters (accumulates ALL matching rules)
- `ConnectionTracker` class - **NEW** Tracks device activity (DNS sniffing, website detection, service identification)
- `BandwidthController` class - Applies traffic control limits using TC (both upload & download)

**Key Features:**
- No user interaction
- Pure networking operations
- Can be imported and used independently
- Thread-safe with locks for concurrent operations
- Real-time packet analysis with scapy
- Activity tracking with timestamp-based recent history (60-second window)
- DNS caching to avoid duplicate records
- Service detection (YouTube, Netflix, Facebook, etc.)

**Recent Improvements:**
- Fixed download speed measurement by accumulating all iptables rules
- Added ConnectionTracker for DNS/activity monitoring
- Enhanced manual bandwidth limiting with both upload and download TC rules

---

#### 2. **ai.py** (21 KB, ~676 lines)
**Intelligent bandwidth management and user interface**

Contains:
- `IntelligentController` class - Wraps BandwidthController with smart algorithms
- `NetMindAI` class - Main system orchestrator
- Auto-balancing algorithm - Detects and limits bandwidth hogs
- Interactive menu system - Manual control interface with 'm' key access
- Activity display - Shows what devices are accessing (YouTube, Netflix, etc.)
- Terminal management - Raw mode for non-blocking keyboard input

**Key Features:**
- High-level bandwidth management
- Automatic decision-making algorithms
- User-friendly CLI interface with real-time updates
- Signal handlers for graceful shutdown (SIGINT, SIGTERM)
- Non-blocking keyboard input using select, tty, and termios
- Dual speed display (KB/s and Mbps)
- Activity summary with service detection
- Proper terminal state restoration on exit

**Recent Improvements:**
- Added 'm' key for menu access (replaced Ctrl+C which shut down the program)
- Implemented terminal raw mode with proper cleanup
- Fixed display duplication bug when returning from menu
- Added input buffer flushing to prevent key queue buildup
- Enhanced activity tracking display with recent connections only

---

#### 3. **NetMind.py** (3.2 KB, ~115 lines)
**Main entry point and orchestrator**

Contains:
- `main()` function - Program startup and mode selection
- Mode selection logic - Automatic vs Manual + AI
- Import statements - Combines tool and AI modules

**Key Features:**
- Clean, minimal startup code
- Mode selection (Automatic/Manual/Rescan)
- Single entry point for the application
- User-friendly messages about 'm' key usage

**Recent Improvements:**
- Updated help messages to explain 'm' key for menu access
- Added clarity about 5-6 second startup delay

---

### **Supporting Files**

- **README.md** (10.5 KB) - Comprehensive documentation with FAQ
- **Setup.py** - Installation script
- **Depandance.txt** - Dependency list
- **requirements.txt** - Python package dependencies

---

## Module Hierarchy

```
NetMind.py (Entry Point)
    ↓
Imports: ai.py
    ↓
ai.py (AI Engine + UI)
    ├─ Imports: tool.py
    ├─ Imports: select, tty, termios (terminal control)
    ├─ Contains: IntelligentController, NetMindAI
    └─ Uses: BandwidthController, ConnectionTracker from tool.py
    ↓
tool.py (Core Networking)
    ├─ Contains: ARPSpoofer, TrafficMonitor, BandwidthController, ConnectionTracker
    ├─ Uses: scapy, iptables, tc commands
    └─ Dependencies: External system utilities
```

---

## Import Chain

### **tool.py**
- No imports from other project files
- External deps: `scapy`, `netifaces`, `termcolor`, `subprocess`, `threading`, `collections`

### **ai.py**
```python
from tool import (
    Config, has_root, get_gateway_ip, get_default_interface, 
    get_subnet_cidr, enable_ip_forwarding, discover_clients,
    TrafficMonitor, BandwidthController, ConnectionTracker
)
import select, tty, termios  # For 'm' key menu access
```

### **NetMind.py**
```python
from ai import NetMindAI, Config
```

---

## Separation of Concerns

### **tool.py** - The Toolbox
- **Responsibility**: Low-level network operations
- **Abstraction Level**: System-level (iptables, tc, ARP, DNS)
- **Coupling**: Only external libraries
- **Testing**: Can be unit tested independently
- **New Features**: 
  - ConnectionTracker for DNS/activity monitoring
  - Enhanced bandwidth controller with download limiting

### **ai.py** - The Brain + Interface
- **Responsibility**: Decision-making and user interaction
- **Abstraction Level**: Application-level (bandwidth strategy + UI)
- **Coupling**: tool.py for operations
- **Testing**: Can be tested with mock Tool objects
- **New Features**: 
  - Terminal raw mode for non-blocking keyboard input
  - Activity tracking integration
  - Improved menu flow without duplicate threads

### **NetMind.py** - The Entry Point
- **Responsibility**: User interaction and flow
- **Abstraction Level**: User interface startup
- **Coupling**: ai.py for engine
- **Testing**: Integration testing

---

## Data Flow

```
User Input (NetMind.py)
    ↓
Mode Selection
    ↓
NetMindAI.start_monitoring()
    ↓
↙─────────────────────┬─────────────────────┬─────────────────────┐
│                     │                     │                     │
ARP Spoofing    Traffic Monitoring    Activity Tracking   Display Stats
(tool.py)       (tool.py)             (tool.py)          (ai.py)
│                │                      │                  │
└─────────────────────┬───────────────────┬──────────────┘
                      ↓                   ↓
            IntelligentController    ConnectionTracker
            (ai.py)                  (DNS sniffing)
            Auto-balancing           Service detection
            Limit Application        Recent activity
                      ↓
        Apply/Remove Limits
        (BandwidthController)
        Upload + Download TC rules
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
    STATE_FILE = "/tmp/netmind_ai_state.json"
```

This Config class is imported and used by `ai.py` for all behavioral parameters.

---

## Execution Flow

### **Automatic Mode**
```
Start → Scan → Monitor → Auto-Balance Loop → Display (press 'm' for menu) → Shutdown
```

### **Manual Mode**
```
Start → Scan → Monitor → Menu (press 'm') → Manual Action → Continue/Stop
```

---

## Key Features & Improvements

### **Activity Tracking** (ConnectionTracker)
- DNS packet sniffing for real-time activity detection
- Service identification (YouTube, Netflix, Facebook, etc.)
- 60-second recent activity window
- DNS caching to prevent duplicates
- Timestamp-based tracking with deque (maxlen=50)

### **Terminal Management**
- Non-blocking keyboard input using select()
- Terminal raw mode (tty.setcbreak)
- Proper terminal state restoration on exit
- Input buffer flushing (termios.tcflush)
- 'm' key for menu access without interrupting program

### **Bandwidth Control**
- Upload and download limiting (separate TC classes)
- Packet marking with iptables mangle table
- HTB queuing discipline
- SFQ per-device fairness
- Both PREROUTING and POSTROUTING chains

### **Speed Measurement**
- Dual display: KB/s and Mbps
- Accumulates all iptables rules for accuracy
- Separate tracking for upload and download
- Real-time updates every 3 seconds

---

## File Sizes & Metrics

| File | Size | Lines | Purpose |
|------|------|-------|---------|
| tool.py | 18.5 KB | ~619 | Core networking |
| ai.py | 21 KB | ~676 | Intelligence & UI |
| NetMind.py | 3.2 KB | ~115 | Entry point |
| README.md | 10.5 KB | ~380 | Documentation |
| **Total** | **53.2 KB** | **~1790** | Complete system |

---

## Code Quality Improvements

✅ **Modularity**: Each file has a single responsibility
✅ **Testability**: Core logic can be tested independently
✅ **Maintainability**: Clear separation makes updates easier
✅ **Reusability**: tool.py can be used independently
✅ **Scalability**: Easy to add new features without affecting existing code
✅ **Bug Fixes**: Download limiting, display duplication, terminal handling
✅ **User Experience**: 'm' key access, activity tracking, dual speed display

---

## Recent Bug Fixes

### 1. **Download Speed Measurement**
- **Issue**: Download readings didn't match phone speed tests
- **Cause**: `_get_bytes()` returned first matching iptables rule only
- **Fix**: Accumulate bytes from ALL matching rules using `total_bytes` variable

### 2. **Activity Tracking Accuracy**
- **Issue**: Showed all-time history instead of recent activity
- **Cause**: No time-based filtering in ConnectionTracker
- **Fix**: Added timestamps, 60-second window, deque with maxlen=50

### 3. **Menu Access Problem**
- **Issue**: Ctrl+C shut down program instead of opening menu
- **Cause**: SIGINT signal handler
- **Fix**: Implemented 'm' key with terminal raw mode and select()

### 4. **Manual Bandwidth Limiting**
- **Issue**: Only upload was limited, not download
- **Cause**: Missing download TC rules and PREROUTING chain
- **Fix**: Added mark+200 for download, separate TC class, PREROUTING mangle rule

### 5. **Display Duplication Bug**
- **Issue**: Duplicate output when returning from menu to live monitoring
- **Cause**: New thread created while original still running
- **Fix**: Changed 'c' option to set running=True and return False, added tcflush

---

## Future Extensibility

The modular structure enables easy addition of:

1. **New Interfaces**
   - Web UI (import NetMindAI from ai.py)
   - REST API (import functions from tool.py)
   - Mobile app (same imports)

2. **New Algorithms**
   - Add methods to IntelligentController in ai.py
   - Keep tool.py untouched

3. **New Monitoring Features**
   - Extend TrafficMonitor or ConnectionTracker in tool.py
   - Add visualization to ai.py

4. **New Bandwidth Strategies**
   - Create new controller subclass in ai.py
   - Use existing BandwidthController from tool.py

5. **Enhanced Activity Detection**
   - Add more services to ConnectionTracker
   - Implement HTTPS SNI parsing
   - Add protocol-specific detection

---

## Technical Dependencies

### System Requirements
- Linux operating system
- Root/sudo privileges
- iptables
- tc (iproute2)
- Python 3.x

### Python Packages
- scapy (ARP spoofing, DNS sniffing)
- netifaces (network interface detection)
- termcolor (colored terminal output)
- select, tty, termios (terminal control)

### External Commands
- iptables (traffic counting, packet marking)
- tc (traffic shaping, bandwidth limiting)
- ip (network configuration)

---

**Last Updated**: January 21, 2026
**Refactoring Version**: 2.0 (with activity tracking, terminal handling, and bug fixes)
