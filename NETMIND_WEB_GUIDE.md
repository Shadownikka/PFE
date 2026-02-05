# 🤖 NetMind AI - Guide d'Installation Interface Web

## ✨ Nouvelle Interface Web avec Chat AI

Interface web moderne pour NetMind AI avec:
- 💬 **Chat AI Intégré** - Parlez naturellement avec l'agent Ollama
- 📊 **Dashboard en Temps Réel** - Visualisation des appareils et bande passante
- 🎯 **Contrôle Intelligent** - L'AI gère automatiquement votre réseau
- ⚡ **Actions Instantanées** - Les changements se voient immédiatement

## 📋 Prérequis

### 1. Ollama Installé et Configuré

```bash
# Installer Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Démarrer Ollama (Terminal séparé)
ollama serve

# Télécharger le modèle Llama 3.1
ollama pull llama3.1
```

### 2. NetMind AI Fonctionnel

Vous devez avoir:
- ✅ `NetMind.py`
- ✅ `ai.py`
- ✅ `tool.py`
- ✅ `net_agent.py`
- ✅ Toutes les dépendances installées

### 3. Flask

```bash
pip3 install flask flask-cors --break-system-packages
```

## 📦 Installation

### Étape 1: Placer les Fichiers

Mettez ces 2 nouveaux fichiers dans votre dossier NetMind:

```bash
cd ~/Downloads/PFE-final  # Votre dossier NetMind

# Vous devez avoir:
# - NetMind.py (existant)
# - ai.py (existant)
# - tool.py (existant)
# - net_agent.py (existant)
# - netmind_backend.py (nouveau)
# - netmind_ai_interface.html (nouveau)
```

### Étape 2: Vérifier la Structure

```bash
ls -la NetMind.py ai.py tool.py net_agent.py netmind_backend.py netmind_ai_interface.html
```

Tous ces fichiers doivent être présents.

## 🚀 Lancement

Vous avez besoin de **3 terminaux**:

### Terminal 1: Ollama Server

```bash
ollama serve
```

Laissez ce terminal ouvert. Vous verrez:
```
Listening on 127.0.0.1:11434
```

### Terminal 2: NetMind Backend avec AI

```bash
cd ~/Downloads/PFE-final
sudo python3 netmind_backend.py
```

Vous verrez:
```
======================================================================
NetMind AI - Web Backend Server
======================================================================

[+] Initializing NetMind AI...
[+] Scanning network...
[+] Found X devices
[+] Starting monitoring...
[+] Initializing AI Agent...
[Agent] Protected IPs: {...}
[✓] AI Agent ready!
[✓] Background monitoring started

======================================================================
Server ready!
Web interface: http://localhost:5000
API endpoint: http://localhost:5000/api/status
======================================================================
```

### Terminal 3: Navigateur

```bash
firefox http://localhost:5000
# ou
google-chrome http://localhost:5000
```

## 💬 Utilisation du Chat AI

### Exemples de Commandes

Dans l'interface de chat, tapez:

#### 1. Diagnostiquer un Problème
```
Vous: I'm lagging, fix it
AI: [Analyzes network] I found device 192.168.1.50 using 12 Mbps. 
    I've limited it to 3 Mbps. Your lag should be fixed!
```

#### 2. Voir les Statistiques
```
Vous: Who is using the most bandwidth?
AI: [Checks stats] Device 192.168.1.50 is using the most 
    bandwidth at 15.2 Mbps download and 2.1 Mbps upload.
```

#### 3. Optimiser le Réseau
```
Vous: Optimize my network
AI: [Analyzes and applies limits] I've optimized your network by 
    limiting 2 devices that were using excessive bandwidth.
```

#### 4. Demander des Infos
```
Vous: Show me current network stats
AI: [Retrieves stats] Here's what I see:
    - 192.168.1.50: 8.5 Mbps down, 1.2 Mbps up (ACTIVE)
    - 192.168.1.51: 2.1 Mbps down, 0.5 Mbps up (ACTIVE)
    - 192.168.1.52: 0.0 Mbps (IDLE)
```

#### 5. Gérer les Limites
```
Vous: Limit the heaviest user to 3 Mbps
AI: [Finds and limits] I've limited device 192.168.1.50 to 3 Mbps 
    download and 1 Mbps upload.
```

#### 6. Retirer des Limites
```
Vous: Remove all limits
AI: [Removes limits] I've removed all bandwidth limits. All devices 
    now have full speed access.
```

### Suggestions Rapides

L'interface propose des suggestions que vous pouvez cliquer:
- "I'm lagging, fix it"
- "Who's using most bandwidth?"
- "Show network stats"
- "Optimize network"

## 📊 Dashboard

L'interface affiche en temps réel:

### Statistiques Globales
- **Total Bandwidth**: Bande passante totale utilisée (Mbps)
- **Active Devices**: Nombre d'appareils actuellement actifs
- **AI Actions**: Nombre d'optimisations/limites appliquées

### Liste des Appareils
Chaque appareil montre:
- 🖥️ **Icône**: Type d'appareil (ordinateur, téléphone, etc.)
- 📍 **IP Address**: Adresse IP de l'appareil
- 📊 **Bandwidth**: Bande passante actuelle (Mbps)
- 🔴 **Status**: 
  - `ACTIVE` (vert) - Utilise activement le réseau
  - `LIMITED` (rouge) - Limite appliquée par l'AI
  - `IDLE` (gris) - Inactif

## 🔧 Fonctionnalités Avancées

### Conversation Contextuelle

L'AI se souvient de la conversation:

```
Vous: Who is using the most bandwidth?
AI: Device 192.168.1.50 is using 12 Mbps.

Vous: Limit it to 3 Mbps
AI: Done! I've limited that device to 3 Mbps.

Vous: Actually, make it 5 Mbps
AI: Updated! The device is now limited to 5 Mbps.
```

### Actions Automatiques

L'AI peut effectuer plusieurs actions en une seule requête:

```
Vous: I need better performance for gaming
AI: [Analyzes] I see 3 devices using high bandwidth. I'll limit them 
    to free up bandwidth for your gaming. 
    [Applies 3 limits]
    Done! Your gaming performance should improve significantly.
```

### Langage Naturel

L'AI comprend différentes façons de demander:
- "I'm lagging" / "Fix my lag" / "Network is slow"
- "Who's hogging bandwidth?" / "Top user?" / "Bandwidth hog?"
- "Limit X to Y Mbps" / "Cap X at Y" / "Restrict X"
- "Show stats" / "What's happening?" / "Network status"

## 🐛 Dépannage

### Problème: "AI Agent not initialized"

**Solution**: Le backend n'a pas pu démarrer NetMind AI

```bash
# Vérifiez que vous avez les permissions root
sudo python3 netmind_backend.py

# Vérifiez que tous les fichiers sont présents
ls -la NetMind.py ai.py tool.py net_agent.py
```

### Problème: "Error communicating with Ollama"

**Solution**: Ollama n'est pas démarré

```bash
# Terminal 1: Démarrer Ollama
ollama serve

# Terminal 2: Vérifier qu'il fonctionne
ollama list
```

### Problème: "Model not found"

**Solution**: Le modèle Llama 3.1 n'est pas installé

```bash
ollama pull llama3.1
```

### Problème: Chat ne répond pas

**Solution**: Vérifiez les logs du backend

Dans Terminal 2, vous devriez voir:
```
[Chat] User: your message
[Chat] AI: response...
```

Si vous ne voyez rien, l'agent n'est pas initialisé correctement.

### Problème: Aucun appareil affiché

**Solution**: NetMind n'a pas scanné le réseau

```bash
# Redémarrez le backend
# Terminal 2: Ctrl+C puis
sudo python3 netmind_backend.py
```

### Problème: "Permission denied"

**Solution**: Lancez avec sudo

```bash
sudo python3 netmind_backend.py
```

## 🎯 Architecture

```
┌─────────────────────┐
│   Navigateur Web    │  ← Interface utilisateur
│   (chat + dashboard)│
└──────────┬──────────┘
           │ HTTP/WebSocket
           ▼
┌─────────────────────┐
│   Flask Backend     │  ← API REST
│   netmind_backend   │
└──────────┬──────────┘
           │
           ├───────────────┐
           │               │
           ▼               ▼
┌─────────────────┐ ┌──────────────┐
│  NetMindAgent   │ │   NetMindAI  │
│  (Ollama)       │ │   (Monitor)  │
└────────┬────────┘ └──────┬───────┘
         │                 │
         ▼                 ▼
┌─────────────────────────────┐
│      Ollama Server          │
│      (Llama 3.1)            │
└─────────────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│   Linux Traffic Control     │
│   (iptables + tc)           │
└─────────────────────────────┘
```

## 📡 API Endpoints

Si vous voulez créer vos propres intégrations:

### GET /api/status
Retourne l'état actuel du système
```json
{
  "total_bandwidth": 45.3,
  "devices": [...],
  "active_devices": 5,
  "optimizations": 2,
  "ai_active": true
}
```

### POST /api/chat
Envoie un message à l'AI
```json
{
  "message": "I'm lagging, fix it",
  "conversation_id": "12345"
}
```

Réponse:
```json
{
  "success": true,
  "response": "I found device...",
  "actions_performed": true
}
```

### GET /api/devices
Liste tous les appareils
```json
{
  "devices": [...],
  "total": 10,
  "active": 5
}
```

### POST /api/agent/reset
Réinitialise la conversation

## 💡 Conseils

1. **Première Utilisation**: Attendez 30 secondes que le système collecte des données

2. **Langage Naturel**: Parlez normalement, pas besoin de commandes spécifiques

3. **Soyez Spécifique**: Plus vous êtes précis, mieux l'AI peut vous aider

4. **Vérifiez les Actions**: Les actions de l'AI s'affichent dans le dashboard

5. **Conversations Longues**: L'AI se souvient du contexte

## 🚀 Mode Production

### Systemd Service

Créez `/etc/systemd/system/netmind-web.service`:

```ini
[Unit]
Description=NetMind AI Web Backend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/user/Downloads/PFE-final
ExecStart=/usr/bin/python3 netmind_backend.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Activez:
```bash
sudo systemctl enable netmind-web
sudo systemctl start netmind-web
sudo systemctl status netmind-web
```

### Logs

```bash
# Voir les logs en temps réel
sudo journalctl -u netmind-web -f

# Voir les derniers logs
sudo journalctl -u netmind-web -n 100
```

## 🎉 Résumé

Pour lancer NetMind AI Web:

```bash
# Terminal 1: Ollama
ollama serve

# Terminal 2: Backend
cd ~/Downloads/PFE-final
sudo python3 netmind_backend.py

# Terminal 3: Navigateur
firefox http://localhost:5000
```

Puis chattez avec l'AI:
- "I'm lagging, fix it"
- "Who's using most bandwidth?"
- "Show me network stats"
- "Optimize my network"

**C'EST TOUT!** 🚀

L'AI gère tout intelligemment pendant que vous profitez d'une interface moderne et intuitive!

---

**Version**: 3.0 (AI Web Interface)
**Date**: February 5, 2026
**Statut**: ✅ Production Ready
