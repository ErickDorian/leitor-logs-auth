# Leitor de Logs Auth

Ferramenta em Python para analisar logs de autenticação (`auth.log`) e detectar padrões suspeitos de acesso.  
O objetivo é treinar habilidades de análise SOC N1 e gerar relatórios claros e simplificados


Funcionalidades:
- Detecta logins em horários suspeitos  
- Identifica tentativas de login sem sucesso  
- Mostra tentativas de descobrir usuários inválidos  
- Aponta possíveis acessos ao `/etc/shadow`  
- Lista atividade por usuário  
- Destaca os IPs externos mais ativos  

# Como usar

- Opção 1: 
- Rodar no Python:
python src/Analyser.py
Insira manualmente o log .auth ou importe através de um arquivo .txt.

-> O resumo do log será gerado dentro do próprio aplicativo (exemplos de logs estão na pasta samples/ <-

- Opção 2: 
- Usar o executável (windows)
Baixe o arquivo .exe na pasta release/ e execute diretamente no Windows.
Insira manualmente o log .auth ou importe através de um arquivo .txt.

-> O resumo do log será gerado dentro do próprio aplicativo (exemplos de logs estão na pasta /samples). <-

# Objetivo
Treinar análise e gerar relatórios simplificados sobre os logs auth gerados dentro do Linux.

# Requisitos
- Python 3.10+ (em caso de execução dentro do Python)
- Tkinter (já vem com Python em muitas distribuições)
- Windows (para execução do .exe localizado dentro da pasta /release)

# Licença
Distribuído sob a licença MIT. Veja /LICENSE para mais detalhes.



