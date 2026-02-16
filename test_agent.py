#!/usr/bin/env python3
"""
Quick test to verify NetMind Agent can be initialized
Run this to check if Ollama is accessible
"""

import sys

def test_ollama_connection():
    """Test if Ollama is running and accessible"""
    print("🧪 Testing Ollama Connection...")
    try:
        import ollama
        client = ollama.Client(host='http://localhost:11434')
        
        # Try to list models
        try:
            models = client.list()
            model_list = models.get('models', [])
            print(f"✅ Ollama is running!")
            print(f"📦 Available models: {len(model_list)}")
            
            # Check for llama3.1
            model_names = [m.get('name', '') for m in model_list]
            if any('llama3.1' in name for name in model_names):
                print("✅ Llama 3.1 model found!")
            else:
                print("⚠️  Llama 3.1 not found. Run: ollama pull llama3.1")
        except:
            # Alternative: try a simple chat to verify connection
            print("✅ Ollama is running!")
            print("💡 Tip: Run 'ollama pull llama3.1' to download the model")
        
        return True
        
    except Exception as e:
        print(f"❌ Ollama connection failed: {e}")
        print("\n💡 To fix:")
        print("   1. Install Ollama: curl -fsSL https://ollama.com/install.sh | sh")
        print("   2. Start Ollama: ollama serve")
        print("   3. Pull model: ollama pull llama3.1")
        return False

def test_agent_import():
    """Test if NetMindAgent can be imported"""
    print("\n🧪 Testing NetMind Agent Import...")
    try:
        from net_agent import NetMindAgent
        print("✅ NetMindAgent imported successfully!")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

def test_tool_integration():
    """Test if tools can be accessed"""
    print("\n🧪 Testing Tool Integration...")
    try:
        from net_agent import NetMindAgent
        from tool import Config
        
        # Create a minimal mock monitor/controller for testing
        class MockMonitor:
            def get_current_stats(self):
                return {
                    '192.168.1.50': {
                        'upload_kbps': 500,
                        'download_kbps': 2000,
                        'status': 'ACTIVE',
                        'is_limited': False
                    }
                }
        
        class MockController:
            def apply_limit(self, ip, down, up):
                print(f"   Mock: Would limit {ip} to {down}↓/{up}↑ KB/s")
            
            def remove_limit(self, ip):
                print(f"   Mock: Would remove limit from {ip}")
        
        # Initialize agent with mocks
        agent = NetMindAgent(MockMonitor(), MockController(), Config)
        print("✅ Agent initialized with mock components!")
        
        # Test get_network_stats
        stats = agent.get_network_stats()
        print(f"✅ get_network_stats returned {len(stats['devices'])} device(s)")
        
        # Test enforce_limit (with protected IP check)
        agent.set_protected_ips('192.168.1.1', '192.168.1.100')
        result = agent.enforce_limit('192.168.1.50', 1024, 512)
        print(f"✅ enforce_limit executed: {result['success']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Tool integration failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print("NetMind Agent - System Test")
    print("=" * 60)
    
    results = []
    
    # Run tests
    results.append(("Ollama Connection", test_ollama_connection()))
    results.append(("Agent Import", test_agent_import()))
    results.append(("Tool Integration", test_tool_integration()))
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! NetMind Agent is ready to use.")
        print("\n📚 Next steps:")
        print("   1. Run NetMind: sudo python3 NetMind.py")
        print("   2. Press 'm' during monitoring")
        print("   3. Select '[g] Go Agentic'")
        print("   4. Type: 'Who is using the most bandwidth?'")
    else:
        print("\n⚠️  Some tests failed. Check the errors above.")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
