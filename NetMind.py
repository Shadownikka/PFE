#!/usr/bin/env python3
"""
NetMind - Intelligent Bandwidth Management System
Main entry point - combines tool and AI modules
Automatic, fair, adaptive bandwidth allocation using real-time traffic analysis
Kali Linux / Ubuntu - Production Ready
"""

import time
from termcolor import colored
from ai import NetMindAI, Config

# -------------------------
# Main
# -------------------------
def main():
    print(colored("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║         🤖 NetMind - Intelligent Bandwidth Manager 🤖        ║
║                                                              ║
║  Automatic • Adaptive • Fair • Machine Learning-Based        ║
║                 + Manual Control Mode                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """, "cyan", attrs=["bold"]))
    
    ai = NetMindAI()
    # Background discovery scanner interval (seconds)
    Config.DISCOVERY_INTERVAL = 10
    print(colored(f"[✓] Background discovery enabled ({Config.DISCOVERY_INTERVAL}s interval)", "green"))
    
    while True:
        ai.scan_network()
        
        if not ai.devices:
            print(colored("[!] No devices found", "red"))
            retry = input(colored("Rescan? (y/n): ", "yellow")).strip().lower()
            if retry != 'y':
                return
            continue
        
        print(colored("\n" + "="*70, "yellow"))
        print(colored("⚙️  MODE SELECTION", "yellow", attrs=["bold"]))
        print(colored("="*70, "yellow"))
        print("\n  [1] 🤖 Automatic AI Mode (AI manages everything)")
        print("  [2] 🎮 Manual + AI Mode (You control, AI assists)")
        print("  [3] 🔄 Rescan Network")
        print("  [4] ❌ Cancel")
        
        mode = input(colored("\n➤ Choose mode: ", "green")).strip()
        
        if mode == '1':
            Config.AUTO_LIMIT_ENABLED = True
            print(colored("\n[+] Starting in AUTOMATIC AI mode...", "cyan"))
            time.sleep(2)
            
            try:
                ai.start_monitoring(mode='auto')
                break  # Normal exit after monitoring
            except KeyboardInterrupt:
                print(colored("\n\n[+] Opening menu...", "cyan"))
                time.sleep(1)
                result = ai.show_menu()
                if result == 'main_menu':
                    print(colored("\n[+] Returning to main menu...\n", "green"))
                    time.sleep(1)
                    continue  # Go back to main menu
                elif result:
                    break  # Quit
                else:
                    print(colored("\n[!] Monitoring completed", "cyan"))
                    break
        elif mode == '2':
            Config.AUTO_LIMIT_ENABLED = False
            print(colored("\n[+] Starting in MANUAL + AI mode...", "cyan"))
            print(colored("[!] Press 'm' key during monitoring to access menu", "yellow"))
            time.sleep(2)
            
            try:
                result = ai.start_monitoring(mode='manual')
                if result == 'main_menu':
                    print(colored("\n[+] Returning to main menu...\n", "green"))
                    time.sleep(1)
                    continue  # Go back to main menu
                break  # Normal exit after monitoring
            except KeyboardInterrupt:
                print(colored("\n\n[+] Opening menu...", "cyan"))
                time.sleep(1)
                result = ai.show_menu()
                if result == 'main_menu':
                    print(colored("\n[+] Returning to main menu...\n", "green"))
                    time.sleep(1)
                    continue  # Go back to main menu
                elif result:
                    print(colored("\n[!] Exiting...", "yellow"))
                    break
                else:
                    # Return to monitoring after menu
                    print(colored("\n[!] Monitoring completed", "cyan"))
                    break
        elif mode == '3':
            print(colored("\n[+] Rescanning network...", "cyan"))
            time.sleep(1)
            continue
        elif mode == '4':
            print(colored("\n[!] Cancelled", "yellow"))
            break
        else:
            print(colored("\n[!] Invalid option", "red"))
            time.sleep(1)

# -------------------------
# Entry Point
# -------------------------
if __name__ == "__main__":
    main()
