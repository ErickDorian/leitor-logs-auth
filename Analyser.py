import re
from collections import Counter
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, scrolledtext

RE_FAILED_NEW = re.compile(r'Failed.*? for (?:invalid user )?(\S+) from (\S+)')
RE_ACCEPTED = re.compile(r'Accepted \S+ for (\S+) from (\S+)')
RE_SUDO_SHADOW = re.compile(r'sudo:.*COMMAND=.*(cat|vim|nano|less|more).*\/etc\/shadow', re.IGNORECASE)

USUARIOS_SERVICO = {"cyrus", "news", "mail", "postfix", "courier"}

def limpar_ip(ip):
    """Remove ::ffff: e sufixos."""
    ip = ip.strip().replace("[", "").replace("]", "")
    if ip.lower().startswith("::ffff:"):
        ip = ip[7:]
    # remove porta se vier tipo 192.168.2.10:22
    if ip.count(".") == 3 and ":" in ip:
        ip = ip.split(":")[0]
    return ip

def is_ip_interno(ip):
    ip = limpar_ip(ip)
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("127.") or ip == "localhost"

def processar(texto):
    linhas = texto.splitlines()
    falhas = 0
    ips = []
    ips_externos = []
    usuarios = Counter()
    atipicos = []
    enumeracao = []
    privilegio = []

    for l in linhas:
        if not l.strip():
            continue

        if "CRON" in l:
            if "session opened for user" in l:
                m = re.search(r'for user (\w+)', l)
                if m:
                    usuarios[m.group(1)] += 1
            continue

        m_fail = RE_FAILED_NEW.search(l)
        if m_fail:
            user, ip_raw = m_fail.groups()
            user = user.strip()
            ip = limpar_ip(ip_raw)
            falhas += 1
            ips.append((ip, user))
            if not is_ip_interno(ip):
                ips_externos.append((ip, user))
            usuarios[user] += 1
            m_hora = re.search(r'\s(\d{2}):\d{2}:\d{2}\s', l)
            if m_hora:
                h = int(m_hora.group(1))
                if h <= 5 or h >= 22 and user.lower() not in USUARIOS_SERVICO:
                    atipicos.append(f" [{h:02d}h] Falha {user} de {ip}")
            if 'invalid user' in l:
                enumeracao.append(f"Tentou user inexistente '{user}' de {ip}")
            continue

        m_acc = RE_ACCEPTED.search(l)
        if m_acc:
            user, ip_raw = m_acc.groups()
            usuarios[user] += 1
            continue

        if 'rhost=' in l and 'authentication failure' in l:
            m_ip = re.search(r'rhost=([^\s;]+)', l)
            m_user = re.search(r'user=([^\s;]+)', l)
            if m_ip and m_user:
                ip = limpar_ip(m_ip.group(1))
                user = m_user.group(1)
                falhas += 1
                ips.append((ip, user))
                if not is_ip_interno(ip):
                    ips_externos.append((ip, user))
                usuarios[user] += 1
                m_hora = re.search(r'\s(\d{2}):\d{2}:\d{2}\s', l)
                if m_hora:
                    h = int(m_hora.group(1))
                    if h <=5 or h>=22 and user.lower() not in USUARIOS_SERVICO:
                        atipicos.append(f" [{h:02d}h] Falha {user} de {ip}")
            continue

        if 'session opened for user' in l:
            m = re.search(r'for user (\w+)', l)
            if m:
                user = m.group(1)
                if user.lower() in USUARIOS_SERVICO:
                    usuarios[user] += 1
                    continue
                usuarios[user] += 1
                m_hora = re.search(r'\s(\d{2}):\d{2}:\d{2}\s', l)
                if m_hora:
                    h = int(m_hora.group(1))
                    if h <=5 or h>=22:
                        atipicos.append(f" [{h:02d}h] Login {user} - {l[:70]}")
            continue

        if RE_SUDO_SHADOW.search(l):
            privilegio.append(l.strip())

    return {
        "total": len(linhas),
        "falhas": falhas,
        "ips": Counter(ips),
        "ips_externos": Counter(ips_externos),
        "usuarios": usuarios,
        "atipicos": atipicos,
        "enumeracao": enumeracao,
        "privilegio": privilegio
    }

def gerar_relatorio(res):
    out = []
    out.append("=== Relatório de Segurança ===")
    out.append(f"📊 Foram analisadas {res['total']} linhas de log.")
    out.append(f"❌ Detectamos {res['falhas']} tentativas de login sem sucesso.\n")

    # Horários atípicos
    if res['atipicos']:
        out.append(f"🚨 Logins em horários suspeitos ({len(res['atipicos'])} eventos):")
        out.extend([f" - {a}" for a in res['atipicos'][:30]])
    else:
        out.append("✅ Nenhum login fora do horário normal foi encontrado.")

    # Enumeração de usuários
    if res['enumeracao']:
        out.append(f"\n⚠️ Tentativas de descobrir usuários ({len(res['enumeracao'])}):")
        for e in set(res['enumeracao']):
            out.append(f" - {e}")

    # Escalada de privilégio
    if res['privilegio']:
        out.append("\n Possível tentativa de ganhar privilégios elevados:")
        for p in res['privilegio']:
            out.append(f" - {p}")

    # Atividade por usuário
    out.append("\n👥 Atividade por usuário:")
    for user, qtd in res['usuarios'].most_common():
        out.append(f" - {user}: {qtd} registros")

    # IPs externos
    if res['ips_externos']:
        (ip, user), qtd = res['ips_externos'].most_common(1)[0]
        out.append(f"\n🌍 Principal origem externa: {ip} usando '{user}' ({qtd} tentativas)")
        out.append("\nTop 5 IPs externos mais ativos:")
        for (ip, user), qtd in res['ips_externos'].most_common(5):
            out.append(f" - {ip} ({user}) : {qtd}x")
    elif res['ips']:
        (ip, user), qtd = res['ips'].most_common(1)[0]
        out.append(f"\n🏠 Atividade interna detectada: {ip} ({user}) - {qtd}x")
        out.append("\nTop 5 IPs internos:")
        for (ip, user), qtd in res['ips'].most_common(5):
            out.append(f" - {ip} ({user}) : {qtd}x")
    else:
        out.append("\nℹ️ Nenhum endereço IP suspeito foi encontrado.")

    # Resumo final
    out.append("\n Resumo:")
    if res['falhas'] > 0:
        out.append("O sistema sofreu tentativas de acesso não autorizado. "
                   "Algumas vieram de fora da rede e ocorreram em horários incomuns.")
    else:
        out.append("Nenhuma tentativa de invasão foi detectada neste conjunto de logs.")

    return "\n".join(out)


def abrir_arquivo():
    path = filedialog.askopenfilename(filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")])
    if not path:
        return
    texto = Path(path).read_text(encoding='utf-8', errors='ignore')
    res = processar(texto)
    txt_saida.delete('1.0', tk.END)
    txt_saida.insert('1.0', gerar_relatorio(res))

def analisar_colado():
    texto = txt_entrada.get('1.0', tk.END)
    res = processar(texto)
    txt_saida.delete('1.0', tk.END)
    txt_saida.insert('1.0', gerar_relatorio(res))

def limpar_tudo():
    txt_entrada.delete('1.0', tk.END)
    txt_saida.delete('1.0', tk.END)

root = tk.Tk()
root.title("Leitor de Logs Auth ")
root.geometry("850x650")

frame_btn = tk.Frame(root)
frame_btn.pack(pady=5)
tk.Button(frame_btn, text="📁 Abrir arquivo.log", command=abrir_arquivo).pack(side='left', padx=5)
tk.Button(frame_btn, text="🧹 Limpar todos os registros", command=limpar_tudo, bg="#ffcccc").pack(side='left', padx=5)

tk.Label(root, text="Ou cole o log aqui:").pack()
txt_entrada = scrolledtext.ScrolledText(root, height=8)
txt_entrada.pack(fill='x', padx=10)
tk.Button(root, text="🔍 Analisar texto colado", command=analisar_colado).pack(pady=5)
txt_saida = scrolledtext.ScrolledText(root, height=22, font=("Consolas", 10))
txt_saida.pack(fill='both', expand=True, padx=10, pady=10)

root.mainloop()