# soc-log-analyzer
Description: Ferramenta Python para análise de logs e detecção de ameaças (Brute Force, SQL Injection, Directory Traversal)
# 🛡️ SOC Log Analyzer

Ferramenta desenvolvida em Python para análise automatizada de logs HTTP,
com detecção de ameaças baseada em assinaturas e mapeamento MITRE ATT&CK.

## 🎯 Objetivo
Simular processos básicos de monitoramento utilizados em ambientes SOC,
automatizando a identificação de comportamentos suspeitos em registros de acesso.

## ⚙️ Funcionalidades
- ✅ Detecção de Brute Force (HTTP 401/403)
- ✅ Detecção de SQL Injection
- ✅ Detecção de Directory Traversal
- ✅ Detecção de Scan de Painel Admin
- ✅ Geração de relatório em `.txt`

## 🗂️ Estrutura do projeto

soc-log-analyzer/
├── analisador.py   # Script principal
├── access.log      # Log simulado para testes
├── relatorio.txt   # Relatório gerado pela ferramenta
└── README.md

## ▶️ Como executar
```bash
python analisador.py
```

## 🧩 Mapeamento MITRE ATT&CK
| Técnica | ID | Descrição |
|---|---|---|
| Brute Force | T1110 | Múltiplas tentativas de login falhas |
| Exploit Public-Facing Application | T1190 | SQL Injection e Directory Traversal |

## 📚 Conceitos aplicados
- MITRE ATT&CK Framework
- OWASP Top 10
- NIST Cybersecurity Framework (Identify, Detect, Respond)

## 👤 Autor
**SrJaques** — Estudante de Cibersegurança / SOC Analyst Jr.
