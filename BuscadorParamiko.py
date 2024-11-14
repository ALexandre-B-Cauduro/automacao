import paramiko
from dicionario import hosts_info

# Função para determinar os comandos com base no fabricante e na escolha
def get_commands_by_manufacturer(manufacturer, choice):
    match (manufacturer.lower(), choice):
        case ("juniper", "serial"):
            return ["show chassis hardware | match Chassis"]
        case ("cisco", "serial"):
            return ["show version | include Processor board ID"]
        case ("huawei", "serial"):
            return ["display version | include ESN"]
        case ("extreme", "serial"):
            return ["show version | include Serial Number"]
        case ("juniper", "interface"):
            return ["show interfaces terse | match up | match inet"]
        case ("cisco", "interface"):
            return ["show ip interface brief | include up"]
        case ("huawei", "interface"):
            return ["display ip interface brief | include up"]
        case ("extreme", "interface"):
            return ["show ipconfig | include gerencia"]
        case _:
            return []

# Função para se conectar e executar os comandos no dispositivo remoto
def connect_and_execute(hostname, username, password, manufacturer, choice):
    try:
        # Cria o cliente SSH
        client = paramiko.SSHClient()

        # Carrega as chaves do sistema e ignora a verificação de host (evitar erro de chave desconhecida)
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Conecta ao dispositivo
        client.connect(hostname, username=username, password=password)
        
        # Obtém os comandos para o fabricante e a escolha
        commands = get_commands_by_manufacturer(manufacturer, choice)
        
        # Executa os comandos
        for command in commands:
            print(f"Executando comando: {command} no dispositivo {hostname}")
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode()
            print(output)
        
        client.close()
    except Exception as e:
        print(f"Erro ao conectar ou executar comandos no dispositivo {hostname}: {e}")

# Função principal para interagir com o usuário
def main(choice):
    # Executar o script para cada host no dicionário
    for host_key, host_info in hosts_info.items():
        hostname = host_info['hostname']
        username = host_info['username']
        password = host_info['password']
        manufacturer = host_info['manufacturer']
        
        # Chama a função de conexão e execução
        connect_and_execute(hostname, username, password, manufacturer, choice)

# Solicita ao usuário escolher entre 'serial' ou 'interface'
if __name__ == "__main__":
    choice = input("Escolha o tipo de comando ('serial' ou 'interface'): ").strip().lower()

    if choice not in ["serial", "interface"]:
        print("Escolha inválida! Por favor, digite 'serial' ou 'interface'.")
    else:
        main(choice)