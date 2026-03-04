# Rapport de Projet de Fin d'Études (PFE)

## NetMind — Système Intelligent de Gestion de Bande Passante

---

> **Filière :** Réseaux & Sécurité Informatique / Génie Informatique  
> **Niveau :** Master / Licence Professionnelle  
> **Projet :** Fin d'études (PFE)  
> **Dépôt GitHub :** [Shadownikka/PFE](https://github.com/Shadownikka/PFE)

---

## Table des Matières

1. [Résumé Exécutif](#1-résumé-exécutif)
2. [Introduction et Contexte](#2-introduction-et-contexte)
3. [Objectifs du Projet](#3-objectifs-du-projet)
4. [Technologies et Bibliothèques Utilisées](#4-technologies-et-bibliothèques-utilisées)
5. [Architecture Système](#5-architecture-système)
6. [Description des Modules](#6-description-des-modules)
7. [Flux de Données](#7-flux-de-données)
8. [Mécanismes Réseau Clés](#8-mécanismes-réseau-clés)
9. [Agent IA — Llama 3.2 via Ollama](#9-agent-ia--llama-32-via-ollama)
10. [Stack de Monitoring — Prometheus & Grafana](#10-stack-de-monitoring--prometheus--grafana)
11. [Interface Utilisateur en Ligne de Commande](#11-interface-utilisateur-en-ligne-de-commande)
12. [Déploiement Docker](#12-déploiement-docker)
13. [Sécurité](#13-sécurité)
14. [Performances](#14-performances)
15. [Cas d'Usage](#15-cas-dusage)
16. [Tests](#16-tests)
17. [Difficultés Rencontrées et Solutions](#17-difficultés-rencontrées-et-solutions)
18. [Conclusion et Perspectives](#18-conclusion-et-perspectives)
19. [Glossaire](#19-glossaire)

---

## 1. Résumé Exécutif

**NetMind** est un système intelligent de surveillance et de gestion de bande passante réseau. Il combine des techniques de manipulation réseau bas-niveau (ARP spoofing, Traffic Control Linux), un agent IA basé sur le modèle de langage **Llama 3.2** (via Ollama), et une stack de monitoring temps réel (**Prometheus + Grafana**) dans une architecture multi-conteneurs **Docker**.

Le système permet à un administrateur réseau de :
- Découvrir automatiquement tous les appareils d'un réseau local
- Capturer et mesurer en temps réel la bande passante consommée par chaque appareil
- Appliquer des limites ou bloquer des appareils via une commande en langage naturel ou automatiquement via l'IA
- Visualiser l'état du réseau dans des tableaux de bord Grafana actualisés toutes les 5 secondes

---

## 2. Introduction et Contexte

La gestion de la bande passante réseau constitue un défi courant dans les environnements domestiques, les petites entreprises et les établissements scolaires. Un seul appareil monopolisant la connexion peut dégrader la qualité de service pour tous les autres utilisateurs.

Les solutions commerciales (routeurs haut de gamme, firewalls d'entreprise) sont souvent coûteuses et inflexibles. **NetMind** propose une alternative open-source, déployable sur n'importe quelle machine Linux connectée au réseau, exploitant des techniques avancées à un coût nul.

Ce projet s'inscrit dans la convergence de deux domaines en pleine expansion :
1. **La sécurité et l'administration réseau** (interception de trafic, contrôle de flux)
2. **L'intelligence artificielle appliquée** (modèles de langage pour la prise de décision autonome)

---

## 3. Objectifs du Projet

| Objectif | Description |
|---|---|
| **Surveillance en temps réel** | Capturer et calculer la bande passante (KB/s) de chaque appareil réseau |
| **Contrôle du trafic** | Appliquer des limitations ou bloquer des appareils via Traffic Control Linux |
| **Automatisation par IA** | Un agent Llama 3.2 prend des décisions autonomes de gestion réseau |
| **Interactivité** | Interface CLI permettant au super-utilisateur de donner des ordres en langage naturel |
| **Observabilité** | Exposition des métriques à Prometheus et visualisation dans Grafana |
| **Portabilité** | Déploiement en un seul `docker-compose up -d` |

---

## 4. Technologies et Bibliothèques Utilisées

### Langage Principal

| Technologie | Version | Rôle |
|---|---|---|
| **Python 3** | ≥ 3.10 | Langage principal de l'application |

### Bibliothèques Python

| Bibliothèque | Rôle |
|---|---|
| `scapy` | Manipulation de paquets réseau : ARP spoofing, sniffing, scanning |
| `netifaces` | Récupération des informations d'interface réseau (IP, MAC, passerelle) |
| `ollama` | Client Python pour communiquer avec le serveur Ollama (LLM) |
| `prometheus_client` | Exposition des métriques au format Prometheus (Gauge, Counter) |
| `termcolor` | Colorisation de la sortie terminal |
| `threading` | Gestion de threads concurrents (sniffing, monitoring, spoofing) |
| `subprocess` | Exécution de commandes système (`iptables`, `tc`) |
| `statistics` | Calcul de moyennes pour l'analyse de trafic |
| `collections.defaultdict / deque` | Structures de données efficaces pour l'historique de trafic |

### Infrastructure & Outils

| Outil | Rôle |
|---|---|
| **Docker & Docker Compose** | Conteneurisation et orchestration de l'ensemble du système |
| **Ollama** | Serveur de modèles de langage (LLM) auto-hébergé |
| **Llama 3.2** | Modèle de langage (≈2 GB) utilisé pour l'agent IA |
| **Prometheus** | Base de données de métriques time-series |
| **Grafana** | Tableau de bord de visualisation |
| **Linux TC (Traffic Control)** | Limitation de bande passante via `tc qdisc/class/filter` |
| **iptables** | Gestion des règles de transfert de paquets |

---

## 5. Architecture Système

### Vue d'Ensemble Multi-Conteneurs

```
┌────────────────────────────────────────────────────────────────────┐
│                        Hôte Docker (Linux)                         │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  netmind-core  (réseau: host, port 9090)                     │  │
│  │  ─────────────────────────────────────────────────────────   │  │
│  │  • NetMind.py     — Point d'entrée, sélection de mode        │  │
│  │  • ai.py          — Moteur principal, boucle de monitoring   │  │
│  │  • tool.py        — ARP spoofing, TC, sniffing réseau        │  │
│  │  • net_agent.py   — Agent IA (function calling avec Llama)   │  │
│  │  • metrics_exporter.py — Serveur HTTP métriques Prometheus   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                    │ HTTP :11435                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  ai-agent  (port 11435:11434)                                │  │
│  │  ─────────────────────────────────────────────────────────   │  │
│  │  • Ollama server            — Serveur d'inférence LLM        │  │
│  │  • Llama 3.2 (~2 GB)        — Modèle de langage              │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                    │ scrape :9090                                   │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  prometheus  (réseau: host, port 9091)                       │  │
│  │  ─────────────────────────────────────────────────────────   │  │
│  │  • Collecte métriques toutes les 3 secondes                  │  │
│  │  • Stockage time-series (rétention 30 jours)                 │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                    │ PromQL :9091                                   │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  grafana  (port 3000)                                        │  │
│  │  ─────────────────────────────────────────────────────────   │  │
│  │  • 10 panneaux de visualisation                              │  │
│  │  • Rafraîchissement automatique toutes les 5 secondes        │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

### Persistance des Données (Volumes Docker)

| Volume | Contenu | Taille estimée |
|---|---|---|
| `ollama_data` | Modèle Llama 3.2 | ~4 GB |
| `prometheus_data` | Séries temporelles des métriques | Variable |
| `grafana_data` | Dashboards, utilisateurs, paramètres | Faible |

---

## 6. Description des Modules

### 6.1 `NetMind.py` — Point d'Entrée

Fichier de démarrage de l'application. Responsabilités :
- Afficher le banner ASCII de bienvenue
- Lancer le scan réseau initial (`ai.scan_network()`)
- Proposer un menu de sélection du mode :
  - **Mode 1 – Automatique IA** : l'IA gère tout de façon autonome
  - **Mode 2 – Manuel + IA** : l'utilisateur contrôle, l'IA assiste
  - **Mode 3 – Rescan** : relance la découverte réseau
- Gérer la boucle principale et les retours au menu

### 6.2 `ai.py` — Moteur Principal

Module central contenant deux classes :

#### `IntelligentController`
Couche de contrôle intelligente au-dessus de `BandwidthController` :
- `apply_limit(ip, down_kbps, up_kbps)` : applique une limite et horodate l'action
- `remove_limit(ip)` : supprime une limite et nettoie les timers
- `auto_balance()` : algorithme d'équilibrage automatique :
  1. Calcule la bande passante totale et par appareil
  2. Si un appareil dépasse le seuil (`BANDWIDTH_ABUSE_THRESHOLD = 5000 KB/s`), calcule une part équitable et applique une limite
  3. Si l'usage se normalise (< 50% du seuil pendant ≥ 60 s), retire la limite
  4. Respecte les `manual_locks` : ne touche jamais les limites appliquées manuellement
- `limits` (propriété) : expose le dictionnaire de limites actives

#### `NetMindAI`
Classe principale orchestrant tout le système :
- Initialisation : vérification root, IP forwarding, interface, passerelle
- `scan_network()` : scan ARP du sous-réseau via `discover_clients()`
- `start_monitoring(mode)` : démarrage de l'ensemble du système
- `_display_loop()` : boucle de monitoring en temps réel avec gestion des entrées clavier non bloquante
- `show_menu()` : menu interactif (limiter, bloquer, débloquer, voir le statut, mode agentique)
- `_apply_limit_interactive()` / `_block_interactive()` : gestion des actions manuelles
- `stop()` : nettoyage propre (arrêt ARP spoofing, restauration des règles iptables/tc)

### 6.3 `tool.py` — Couche Réseau Bas Niveau

#### `Config` — Configuration Globale
```python
MONITOR_INTERVAL      = 3        # Secondes entre chaque mesure
HISTORY_LENGTH        = 20       # Nombre de mesures conservées en historique
MAX_SINGLE_DEVICE_PERCENT = 40   # % max de bande passante par appareil
MIN_GUARANTEED_KBPS   = 256      # Débit minimum garanti par appareil (KB/s)
BANDWIDTH_ABUSE_THRESHOLD = 5000 # Seuil déclenchant une limite automatique (KB/s)
AUTO_LIMIT_ENABLED    = True     # Active/désactive l'auto-limitation
```

#### `ARPSpoofer` — Empoisonnement ARP
- Implémente une attaque Man-in-the-Middle (MITM) bidirectionnelle
- Envoie des réponses ARP falsifiées toutes les 0,5 secondes :
  - Vers la cible : "je suis la passerelle" (adresse MAC de l'hôte)
  - Vers la passerelle : "je suis la cible" (adresse MAC de l'hôte)
- `stop()` : restaure les vraies associations ARP (5 paquets de correction)

#### `TrafficMonitor` — Capture et Mesure du Trafic
- `_packet_handler(packet)` : traite chaque paquet capturé par Scapy
  - Incrémente des compteurs d'octets par adresse IP source/destination
- `_monitor_loop()` : calcule toutes les `MONITOR_INTERVAL` secondes les débits en KB/s
  - `up_kbps = (delta_octets_up / 1024) / MONITOR_INTERVAL`
  - Conservation de l'historique dans une `deque` de taille `HISTORY_LENGTH`
- `get_average_usage(ip, duration)` : moyenne glissante sur les `duration` dernières secondes

#### `BandwidthController` — Contrôle du Trafic TC
- Utilise les commandes Linux `tc` (Traffic Control) pour créer des files d'attente HTB (Hierarchical Token Bucket)
- `apply_limit(ip, down_kbps, up_kbps)` : séquence de commandes TC :
  ```
  tc qdisc add dev eth0 root handle 1: htb default 10
  tc class add dev eth0 parent 1: classid 1:10 htb rate {down_kbps}kbps
  tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dst {ip} flowid 1:10
  ```
- `remove_limit(ip)` : supprime les règles TC associées à l'IP

#### `ConnectionTracker` — Suivi des Connexions
- Sniffe les paquets DNS pour résoudre les noms de domaine visités
- Maintient un historique des connexions (IP distantes, domaines, ports) par appareil
- Utilisé pour afficher l'activité réseau dans le menu de statut

### 6.4 `net_agent.py` — Agent IA (Function Calling)

Implémente un agent conversationnel qui utilise Llama 3.2 avec le mécanisme de **function calling** (appel de fonctions) d'Ollama.

#### Outils (Tools) exposés au LLM

| Fonction | Description |
|---|---|
| `get_network_stats` | Récupère les statistiques en temps réel de tous les appareils |
| `enforce_limit` | Applique une limite de bande passante (down/up en KB/s) |
| `remove_limit` | Retire une limite et restaure la pleine vitesse |
| `block_device` | Bloque complètement l'accès Internet d'un appareil (limite à 1 KB/s) |
| `unblock_device` | Débloque un appareil précédemment bloqué |

#### Boucle de Raisonnement
```
Utilisateur: "Limite l'appareil 192.168.1.50 à 1 Mbps"
    ↓
LLM reçoit le message + liste des outils disponibles
    ↓
LLM génère un appel d'outil: enforce_limit(ip="192.168.1.50", download_kbps=1024, upload_kbps=256)
    ↓
Python exécute BandwidthController.apply_limit(...)
    ↓
Résultat renvoyé au LLM (succès/échec)
    ↓
LLM formule une réponse en langage naturel
    ↓
Affichage à l'utilisateur
```

#### Garde-fous de Sécurité
- `protected_ips` : ensemble d'IPs jamais limitées (passerelle + hôte)
- Validation des paramètres entrants (conversion `int`, vérifications `True/False`)
- `manual_locks` dans `ai.py` : l'IA ne peut pas retirer les limites appliquées manuellement

### 6.5 `metrics_exporter.py` — Export Prometheus

Expose les métriques NetMind au format Prometheus via un serveur HTTP sur le port 9090.

#### Métriques Définies

| Métrique | Type | Description |
|---|---|---|
| `netmind_bandwidth_download_kbps` | Gauge | Débit de téléchargement par appareil (KB/s) |
| `netmind_bandwidth_upload_kbps` | Gauge | Débit d'envoi par appareil (KB/s) |
| `netmind_bandwidth_total_download_mb` | Gauge | Total téléchargé depuis le démarrage (MB) |
| `netmind_bandwidth_total_upload_mb` | Gauge | Total envoyé depuis le démarrage (MB) |
| `netmind_device_status` | Gauge | État : 0=normal, 1=limité, 2=bloqué |
| `netmind_device_limit_download_kbps` | Gauge | Limite de téléchargement appliquée |
| `netmind_device_limit_upload_kbps` | Gauge | Limite d'envoi appliquée |
| `netmind_active_devices_total` | Gauge | Nombre d'appareils actifs (> 1 KB/s) |
| `netmind_limited_devices_total` | Gauge | Nombre d'appareils limités |
| `netmind_blocked_devices_total` | Gauge | Nombre d'appareils bloqués |
| `netmind_network_total_download_kbps` | Gauge | Débit total du réseau (téléchargement) |
| `netmind_network_total_upload_kbps` | Gauge | Débit total du réseau (envoi) |
| `netmind_limits_applied_total` | Counter | Nombre total de limitations appliquées |
| `netmind_limits_removed_total` | Counter | Nombre total de limitations supprimées |
| `netmind_ai_inference_time_seconds` | Gauge | Temps d'inférence de l'agent IA (secondes) |
| `netmind_ai_decisions_total` | Counter | Nombre total de décisions prises par l'IA |
| `netmind_ai_agent_status` | Gauge | État IA : 0=inactif, 1=actif, 2=erreur |
| `netmind_monitoring_uptime_seconds` | Gauge | Durée depuis le démarrage du monitoring |

Chaque métrique par appareil porte des **labels** : `ip`, `mac`, `hostname`.

---

## 7. Flux de Données

```
Appareils du Réseau Local
    │
    │  (trafic normal vers Internet)
    ▼
Interface Réseau de l'Hôte (eth0)
    │
    │  [ARP Spoofing: l'hôte intercepte TOUT le trafic]
    ▼
Scapy (sniff dans TrafficMonitor + ConnectionTracker)
    │
    │  [compteurs d'octets par IP, toutes les 3 secondes]
    ▼
TrafficMonitor.stats  ←──────── Historique (deque de 20 mesures)
    │
    ├──► IntelligentController.auto_balance()
    │        └── BandwidthController → commandes `tc` → limitation TC
    │
    ├──► NetMindAgent (si mode agentique)
    │        └── Ollama/Llama 3.2 → function calling → BandwidthController
    │
    └──► MetricsExporter.update_metrics() [toutes les 3 s]
             │
             ▼
         HTTP :9090/metrics  (format Prometheus)
             │
             ▼
         Prometheus (scrape toutes les 3 s, stocke en time-series)
             │
             ▼
         Grafana (requêtes PromQL, affichage toutes les 5 s)
             │
             ▼
         Navigateur de l'Administrateur
```

---

## 8. Mécanismes Réseau Clés

### 8.1 ARP Spoofing (MITM)

Le protocole ARP (Address Resolution Protocol) est utilisé par les appareils réseau pour associer une adresse IP à une adresse MAC. Il est intrinsèquement non authentifié.

NetMind exploite cette faiblesse en envoyant de fausses réponses ARP :

```
Situation normale :
  Appareil (192.168.1.50)  ←→  Passerelle (192.168.1.1)
  (ARP: gateway_IP → gateway_MAC)

Après ARP Spoofing :
  Appareil (192.168.1.50)  →  Hôte NetMind (192.168.1.100)  →  Passerelle (192.168.1.1)
  (ARP: gateway_IP → host_MAC)    (IP forwarding activé)
```

Grâce à l'IP forwarding activé sur l'hôte (`/proc/sys/net/ipv4/ip_forward = 1`) et aux règles iptables (`FORWARD ACCEPT`), le trafic est retransmis normalement et les appareils ne perçoivent aucune interruption.

### 8.2 Contrôle du Trafic Linux (TC / HTB)

Linux Traffic Control avec le discipline `htb` (Hierarchical Token Bucket) permet de limiter précisément le débit par adresse IP :

```bash
# 1. Création d'une qdisc racine HTB sur l'interface
tc qdisc add dev eth0 root handle 1: htb default 10

# 2. Création d'une classe avec le débit limité
tc class add dev eth0 parent 1: classid 1:10 htb rate 512kbps

# 3. Filtre associant l'IP à la classe
tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dst 192.168.1.50 flowid 1:10
```

La limitation s'applique aux paquets **transitant par l'hôte** (grâce au MITM ARP), ce qui permet de contrôler le trafic de n'importe quel appareil du réseau.

### 8.3 IP Forwarding et iptables

```python
# Activation du forwarding IP (les paquets destinés à d'autres IPs sont transmis)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Politique FORWARD à ACCEPT (tous les paquets sont forwardés)
iptables -P FORWARD ACCEPT
iptables -A FORWARD -j ACCEPT
```

Ces règles sont critiques : sans elles, l'hôte accepterait les paquets mais ne les transmettrait pas, coupant ainsi l'accès Internet des cibles.

---

## 9. Agent IA — Llama 3.2 via Ollama

### 9.1 Architecture de l'Agent

L'agent IA repose sur le patron d'architecture **ReAct** (Reasoning + Acting) via le mécanisme de function calling d'Ollama :

```
┌─────────────────────────────────────────────┐
│              Utilisateur (CLI)               │
│  "Qui utilise le plus de bande passante ?"   │
└─────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│           NetMindAgent.chat()                │
│  • Construction du prompt système           │
│  • Ajout du message utilisateur             │
│  • Envoi à l'API Ollama avec outils définis │
└─────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│         Llama 3.2 (Ollama Server)            │
│  • Analyse le contexte                      │
│  • Décide d'appeler get_network_stats()     │
│  • Génère un appel de fonction JSON         │
└─────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│          execute_function()                  │
│  • Récupère les vraies statistiques réseau  │
│  • Retourne les données au LLM              │
└─────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│         Llama 3.2 (réponse finale)           │
│  "L'appareil 192.168.1.50 utilise 4.2 Mbps  │
│   en téléchargement. Voulez-vous le limiter?"│
└─────────────────────────────────────────────┘
```

### 9.2 Optimisation pour Inférence < 30 Secondes

```python
options = {
    'temperature': 0.2,   # Déterministe → plus rapide
    'num_predict': 150,   # Réponses courtes
    'top_k': 5,           # Échantillonnage restreint → plus rapide
    'top_p': 0.85,
    'num_ctx': 2048,      # Fenêtre de contexte réduite → moins de mémoire
}
```

L'historique de conversation est limité aux **3 derniers échanges** pour éviter une croissance du contexte qui ralentirait les inférences.

### 9.3 Prompt Système

```
NetMind bandwidth manager. Be concise.

Rules:
- Check stats: get_network_stats
- Active: >1 kbps
- Limits: 512-5120 KB/s
- NEVER limit gateway
- Block = block_device (not enforce_limit 0)

Commands:
"Block everyone except X" = block ALL but X
"Block only X" = block X only
State what you DID (past tense).
```

Ce prompt minimal est conçu pour maximiser la vitesse d'inférence tout en guidant le comportement de l'IA.

---

## 10. Stack de Monitoring — Prometheus & Grafana

### 10.1 Prometheus

Prometheus est une base de données de séries temporelles (TSDB) spécialisée dans la collecte de métriques. Dans NetMind :

- **Cible** : `http://localhost:9090/metrics` (serveur Python exposé par `metrics_exporter.py`)
- **Intervalle de collecte** : 3 secondes
- **Rétention** : 30 jours

Configuration (`prometheus.yml`) :
```yaml
scrape_configs:
  - job_name: 'netmind'
    scrape_interval: 3s
    static_configs:
      - targets: ['localhost:9090']
```

### 10.2 Grafana — Tableau de Bord

**10 panneaux de visualisation** provisionnés automatiquement :

| # | Panneau | Type | Description |
|---|---|---|---|
| 1 | AI Performance Gauge | Jauge | Temps d'inférence IA (rouge si ≥ 30 s) |
| 2 | Real-Time Bandwidth | Time series | Débit en temps réel par appareil |
| 3 | Active Devices | Stat | Nombre d'appareils actifs |
| 4 | Limited Devices | Stat | Nombre d'appareils limités |
| 5 | Blocked Devices | Stat | Nombre d'appareils bloqués |
| 6 | Per-Device Download | Bar chart | Téléchargement par appareil |
| 7 | Per-Device Upload | Bar chart | Envoi par appareil |
| 8 | Device Status Table | Table | État complet de chaque appareil |
| 9 | AI Actions Rate | Time series | Fréquence des actions IA |
| 10 | AI Status | Stat | État de l'agent IA |

Accès : `http://localhost:3000` (admin / admin par défaut)

### 10.3 Provisionnement Automatique

Grafana est configuré au démarrage via des fichiers YAML montés en volume :
- `datasources.yml` : configure la source de données Prometheus
- `dashboards.yml` : indique le répertoire des dashboards JSON
- `netmind-dashboard.json` / `netmind-professional-dashboard.json` : définitions des panneaux

---

## 11. Interface Utilisateur en Ligne de Commande

### 11.1 Menu Principal

```
╔══════════════════════════════════════════════════════════════╗
║         🤖 NetMind - Intelligent Bandwidth Manager 🤖        ║
╚══════════════════════════════════════════════════════════════╝

  [1] 🤖 Automatic AI Mode
  [2] 🎮 Manual + AI Mode
  [3] 🔄 Rescan Network
  [4] ❌ Cancel
```

### 11.2 Commandes Pendant le Monitoring

| Touche | Action |
|---|---|
| `l` | Appliquer une limite de bande passante |
| `b` | Bloquer un ou plusieurs appareils |
| `r` | Supprimer une limite |
| `s` | Afficher le statut détaillé d'un appareil (connexions, domaines visités) |
| `x` | Restaurer tous les appareils (supprimer toutes les limites) |
| `g` | Passer en mode agentique (chat IA) |
| `q` | Quitter proprement (avec nettoyage ARP) |

### 11.3 Sélection Multi-Appareils

L'utilisateur peut saisir :
- Un seul index : `1`
- Plusieurs index : `1,3,5`
- Tous les appareils : `all`

---

## 12. Déploiement Docker

### 12.1 Structure des Conteneurs

```yaml
services:
  netmind-core:      # Conteneur principal (mode réseau: host, privilégié)
  ai-agent:          # Ollama + Llama 3.2 (port 11435)
  prometheus:        # Collecte métriques (port 9091)
  grafana:           # Dashboards (port 3000)
```

### 12.2 Modes Réseau

**`network_mode: host`** (netmind-core, prometheus) :
- Le conteneur partage la pile réseau de l'hôte
- Indispensable pour que `iptables` et `tc` opèrent sur les vraies interfaces réseau
- Permet à Scapy de capturer les paquets en transit

**Bridge network** (ai-agent, grafana) :
- Réseau isolé avec mapping de ports
- Pas besoin d'accès au réseau hôte

### 12.3 Privilèges

```yaml
netmind-core:
  privileged: true   # Requis pour :
  # - iptables (gestion des règles de pare-feu)
  # - tc (traffic control)
  # - Raw sockets (Scapy)
  # - Écriture dans /proc/sys/net/ipv4/ip_forward
```

### 12.4 Démarrage Rapide

```bash
# 1. Lancer tous les services
sudo docker-compose up -d

# 2. Attendre le téléchargement de Llama 3.2 (~2 GB, 5-10 min)
sudo docker logs -f netmind-ai-agent

# 3. Lancer l'interface NetMind
sudo docker exec -it netmind-core python3 NetMind.py
```

---

## 13. Sécurité

### 13.1 Considérations Générales

| Aspect | Analyse |
|---|---|
| **ARP Spoofing** | Technique légalement sensible — à utiliser uniquement sur des réseaux dont vous êtes propriétaire ou administrateur légalement autorisé |
| **Conteneur privilégié** | `privileged: true` donne un accès quasi-total à l'hôte. Justifié fonctionnellement mais représente un risque si le conteneur est compromis |
| **Réseau hôte** | L'accès total au réseau de l'hôte est nécessaire mais élargit la surface d'attaque |
| **Grafana** | Le mot de passe par défaut `admin/admin` doit être changé en production |
| **Prometheus** | Pas d'authentification par défaut ; accessible uniquement en localhost (port local) |
| **Endpoint métriques** | Port 9090 non protégé ; à sécuriser par pare-feu en environnement de production |

### 13.2 Garde-fous Implémentés

1. **IPs protégées** : la passerelle et l'hôte ne peuvent jamais être limités ou bloqués
2. **Manual locks** : les limites appliquées manuellement ne peuvent pas être supprimées par l'IA
3. **Anti-flapping** : un délai minimum de 60 secondes est imposé avant de retirer une limite automatique
4. **Restauration ARP** : à l'arrêt, 5 paquets ARP corrects sont envoyés pour restaurer les tables ARP

---

## 14. Performances

### 14.1 Ressources Système Estimées

| Composant | RAM | CPU |
|---|---|---|
| netmind-core | ~100 MB | < 10 % |
| ai-agent (Llama 3.2) | ~4 GB | Variable (CPU/GPU) |
| prometheus | ~200 MB | < 5 % |
| grafana | ~100 MB | < 5 % |
| **Total** | **~4,4 GB** | **< 20 % (hors inférence IA)** |

### 14.2 Latences

| Opération | Latence |
|---|---|
| Scan réseau ARP | 2-3 secondes |
| Calcul des débits | 3 secondes (intervalle de monitoring) |
| Mise à jour métriques Prometheus | 3 secondes |
| Rafraîchissement Grafana | 5 secondes |
| Inférence Llama 3.2 (optimisée) | < 30 secondes |
| Application d'une règle TC | < 1 seconde |

### 14.3 Optimisations Clés

- **Threads démons** : tous les threads de fond (sniffing, monitoring, spoofing) sont des démons Python — ils se terminent automatiquement avec le processus principal
- **`store=False` dans Scapy** : les paquets ne sont pas stockés en mémoire, uniquement traités
- **`deque(maxlen=N)`** : historique à taille fixe pour éviter une fuite mémoire
- **Contexte LLM limité** : `num_ctx: 2048` et historique tronqué aux 3 derniers échanges

---

## 15. Cas d'Usage

| Cas d'Usage | Description |
|---|---|
| **Réseau domestique** | Empêcher un appareil (console de jeu, TV en streaming) de saturer la connexion familiale |
| **Petite entreprise** | Garantir une bande passante minimale pour les outils de travail critique |
| **Contrôle parental** | Limiter ou bloquer l'accès Internet d'un appareil à certaines heures |
| **Appareils IoT** | Surveiller la consommation réseau d'objets connectés suspects |
| **Tests de performance** | Simuler une connexion lente pour tester la résilience d'une application |
| **Audit réseau** | Identifier les appareils inconnus et leur consommation de bande passante |

---

## 16. Tests

Le fichier `test_agent.py` fournit trois tests automatisés :

### Test 1 : Connexion Ollama
Vérifie qu'Ollama est démarré et accessible, et que le modèle Llama 3.2 est disponible.

### Test 2 : Import de l'Agent
Vérifie que `NetMindAgent` peut être importé sans erreur.

### Test 3 : Intégration des Outils
- Crée des implémentations mock de `TrafficMonitor` et `BandwidthController`
- Instancie `NetMindAgent` avec ces mocks
- Vérifie que `get_network_stats()` retourne une structure valide
- Vérifie que `enforce_limit()` retourne un résultat structuré avec `success`

```bash
# Exécution des tests
python3 test_agent.py
```

Sortie attendue :
```
✅ PASS - Ollama Connection
✅ PASS - Agent Import
✅ PASS - Tool Integration
Total: 3/3 tests passed
```

---

## 17. Difficultés Rencontrées et Solutions

| Difficulté | Solution Adoptée |
|---|---|
| **Temps d'inférence IA trop long** | Réduction de `num_ctx`, `num_predict`, `top_k` ; prompt système minimal |
| **Flapping des limites** (appliquées/retirées en boucle) | `MIN_LIMIT_DURATION = 60 s` : délai minimum avant retrait d'une limite |
| **Coupure réseau à l'arrêt brutal** | Gestionnaire de signal `SIGINT/SIGTERM` + restauration ARP propre |
| **Métriques non mises à jour sans trafic** | Vérification `if not self.ai.devices` avant mise à jour |
| **Confusion IA : bloquer vs limiter à 0** | Instruction explicite dans le prompt : `Block = block_device (not enforce_limit 0)` |
| **Conflits de ports Docker** | Ports distincts pour chaque service : 9090, 9091, 11435, 3000 |
| **Grafana ne trouve pas Prometheus** | Utilisation de `host.docker.internal:host-gateway` dans `docker-compose.yml` |

---

## 18. Conclusion et Perspectives

### Résultats Obtenus

NetMind démontre qu'il est possible de construire un système complet de gestion de bande passante réseau en combinant :
- Des techniques réseau avancées (ARP spoofing, Traffic Control Linux)
- Un agent IA conversationnel (Llama 3.2 avec function calling)
- Une stack de monitoring industrielle (Prometheus + Grafana)
- Le tout déployable en quelques minutes via Docker Compose

### Perspectives d'Amélioration

| Amélioration | Priorité | Description |
|---|---|---|
| **Interface Web** | Haute | Remplacer le CLI par une interface web (Flask/FastAPI + React) |
| **Authentification Prometheus** | Haute | Sécuriser l'endpoint métriques avec Basic Auth |
| **Multi-sous-réseau** | Moyenne | Surveiller plusieurs sous-réseaux simultanément |
| **Règles planifiées** | Moyenne | Appliquer des limites selon un calendrier (ex. : nuit/jour) |
| **Détection d'anomalies** | Moyenne | ML pour détecter des comportements réseau suspects |
| **Support IPv6** | Basse | Étendre la surveillance aux adresses IPv6 |
| **Notifications** | Basse | Alertes par email/Telegram lors d'événements réseau |
| **GPU pour l'IA** | Basse | Accélération de l'inférence Llama via CUDA/ROCm |

---

## 19. Glossaire

| Terme | Définition |
|---|---|
| **ARP** | Address Resolution Protocol — protocole de résolution IP → MAC |
| **ARP Spoofing** | Envoi de fausses réponses ARP pour rediriger le trafic vers l'attaquant |
| **MITM** | Man-in-the-Middle — positionnement de l'hôte entre la cible et la passerelle |
| **TC** | Traffic Control — outil Linux de gestion des files d'attente réseau |
| **HTB** | Hierarchical Token Bucket — algorithme de limitation de débit dans TC |
| **iptables** | Outil Linux de configuration du pare-feu et des règles de routage |
| **Scapy** | Bibliothèque Python de manipulation de paquets réseau |
| **Ollama** | Serveur d'inférence de modèles de langage auto-hébergé |
| **LLM** | Large Language Model — modèle de langage de grande taille (ex. Llama 3.2) |
| **Function Calling** | Capacité d'un LLM à générer des appels de fonctions structurés |
| **Prometheus** | Base de données time-series pour la collecte de métriques |
| **Grafana** | Outil de visualisation et de tableau de bord pour les métriques |
| **PromQL** | Prometheus Query Language — langage de requêtes pour Prometheus |
| **Gauge** | Métrique Prometheus représentant une valeur instantanée (peut monter/descendre) |
| **Counter** | Métrique Prometheus cumulative (ne peut qu'augmenter) |
| **Docker Compose** | Outil d'orchestration multi-conteneurs Docker |
| **KB/s** | Kilobytes par seconde (unité de débit réseau) |
| **TSDB** | Time Series Database — base de données spécialisée dans les séries temporelles |

---

*Rapport généré à partir du code source du dépôt [Shadownikka/PFE](https://github.com/Shadownikka/PFE).*
