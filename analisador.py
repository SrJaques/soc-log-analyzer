import re
from collections import defaultdict
from datetime import datetime

LIMIAR_BRUTE_FORCE = 5  # quantas falhas seguidas = suspeito

PADROES_ATAQUE = {                                        
    "Directory Traversal": r"\.\./",
    "SQL Injection":       r"(SELECT|UNION|INSERT|DROP)",
    "Scan de Admin":       r"/(admin|wp-admin|phpmyadmin|manager)",
}

def ler_log(caminho_arquivo):
    padrao_linha = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<data>[^\]]+)\] '  
        r'"(?P<metodo>\S+) (?P<url>\S+) \S+" '        
        r'(?P<status>\d{3}) (?P<tamanho>\d+)'
    )

    registros = []                                        
    with open(caminho_arquivo, "r") as arquivo:
        for linha in arquivo:
            match = padrao_linha.match(linha)
            if match:
                registros.append(match.groupdict())      

    return registros

def detectar_brute_force(registros):                      
    falhas_por_ip = defaultdict(int)
    alertas = []

    for r in registros:
        if r["status"] in ("401", "403"):                 
            falhas_por_ip[r["ip"]] += 1

    for ip, contagem in falhas_por_ip.items():           
        if contagem >= LIMIAR_BRUTE_FORCE:
            alertas.append({
                "tipo":       "Brute Force",
                "ip":         ip,
                "detalhe":    f"{contagem} tentativas falhas (HTTP 401/403)",
                "mitre":      "T1110 - Brute Force",
                "severidade": "ALTA"
            })

    return alertas

def detectar_ataques_url(registros):
    alertas = []

    for r in registros:
        for nome_ataque, padrao in PADROES_ATAQUE.items():  
            if re.search(padrao, r["url"], re.IGNORECASE):  
                alertas.append({
                    "tipo":       nome_ataque,
                    "ip":         r["ip"],
                    "detalhe":    f"URL suspeita: {r['url']}",
                    "mitre":      "T1190 - Exploit Public-Facing Application",
                    "severidade": "ALTA"                    
                })

    return alertas

def gerar_relatorio(alertas):
    agora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")  
    linhas = []

    linhas.append("=" * 60)
    linhas.append("  RELATORIO DE ANALISE DE LOGS - SOC ANALYZER")
    linhas.append(f"  Gerado em: {agora}")
    linhas.append("=" * 60)

    if not alertas:
        linhas.append("\n Nenhuma atividade suspeita detectada.")  
    else:
        linhas.append(f"\n {len(alertas)} ALERTA(S) DETECTADO(S):\n")
        for i, alerta in enumerate(alertas, 1):
            linhas.append(f"--- Alerta #{i} ---")
            linhas.append(f"  Tipo:       {alerta['tipo']}")
            linhas.append(f"  IP:         {alerta['ip']}")
            linhas.append(f"  Detalhe:    {alerta['detalhe']}")
            linhas.append(f"  MITRE:      {alerta['mitre']}")
            linhas.append(f"  Severidade: {alerta['severidade']}")
            linhas.append("")

    linhas.append("=" * 60)
    relatorio = "\n".join(linhas)                         

    print(relatorio)

    with open("relatorio.txt", "w", encoding="utf-8") as f:
        f.write(relatorio)                                 

    print("\nRelatorio salvo em: relatorio.txt")           

if __name__ == "__main__":
    print("Iniciando analise de logs...\n")

    registros     = ler_log("access.log")
    alertas_bf    = detectar_brute_force(registros)
    alertas_url   = detectar_ataques_url(registros)
    todos_alertas = alertas_bf + alertas_url

    gerar_relatorio(todos_alertas)