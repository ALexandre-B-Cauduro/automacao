import paramiko
import pynetbox
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from typing import Dict
import logging
import os

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("script.log"), logging.StreamHandler()]
)

# Ignora avisos de certificado
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Função para inicializar a conexão com o NetBox
def init_netbox(url: str, token: str) -> pynetbox.core.api.Api:
    try:
        nb = pynetbox.api(url, token)
        nb.http_session.verify = False  # Desabilita a verificação SSL (em caso de certificado autoassinado)
        logging.info("Conexão com o NetBox estabelecida.")
        return nb
    except Exception as e:
        logging.error(f"Erro ao inicializar a conexão com o NetBox: {e}")
        raise

# Função para determinar os comandos com base no fabricante e na escolha
def get_commands_by_manufacturer(manufacturer, choice):
    commands = {
        ("juniper", "serial"): ["show chassis hardware | match Chassis"],
        ("cisco", "serial"): ["show version | include Processor board ID"],
        ("huawei", "serial"): ["display version | include ESN"],
        ("extreme", "serial"): ["show version | include Serial Number"],
        ("juniper", "interface"): ["show interfaces terse | match up | match inet"],
        ("cisco", "interface"): ["show ip interface brief | include up"],
        ("huawei", "interface"): ["display ip interface brief | include up"],
        ("extreme", "interface"): ["show ipconfig | include gerencia"]
    }
    return commands.get((manufacturer.lower(), choice), [])

# Função para se conectar e executar os comandos no dispositivo remoto
def connect_and_execute(hostname, username, password, manufacturer, choice):
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, password=password)
        
        commands = get_commands_by_manufacturer(manufacturer, choice)
        if not commands:
            logging.warning(f"Nenhum comando definido para o fabricante {manufacturer} e escolha {choice}.")
            return {}
        
        interface_data = {}  # Dicionário para armazenar as interfaces e IPs

        for command in commands:
            logging.info(f"Executando comando: {command} no dispositivo {hostname}")
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode()
            logging.info(f"Saída do comando no dispositivo {hostname}:\n{output}")

            # Processar as interfaces e IPs a partir do comando executado
            if choice == "interface":
                for line in output.splitlines():
                    if 'up' in line:  # Ajuste conforme o formato real
                        interface_name, ip_address = parse_interface_output(line)
                        interface_data[interface_name] = ip_address

        client.close()
        return interface_data
    except paramiko.SSHException as e:
        logging.error(f"Erro de conexão SSH com o dispositivo {hostname}: {e}")
        return {}
    except Exception as e:
        logging.error(f"Erro ao executar comandos no dispositivo {hostname}: {e}")
        return {}
import paramiko
import pynetbox
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from typing import Dict
import logging
import os

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("script.log"), logging.StreamHandler()]
)

# Ignora avisos de certificado
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Função para inicializar a conexão com o NetBox
def init_netbox(url: str, token: str) -> pynetbox.core.api.Api:
    try:
        nb = pynetbox.api(url, token)
        nb.http_session.verify = False  # Desabilita a verificação SSL (em caso de certificado autoassinado)
        logging.info("Conexão com o NetBox estabelecida.")
        return nb
    except Exception as e:
        logging.error(f"Erro ao inicializar a conexão com o NetBox: {e}")
        raise

# Função para determinar os comandos com base no fabricante e na escolha
def get_commands_by_manufacturer(manufacturer, choice):
    commands = {
        ("juniper", "serial"): ["show chassis hardware | match Chassis"],
        ("cisco", "serial"): ["show version | include Processor board ID"],
        ("huawei", "serial"): ["display version | include ESN"],
        ("extreme", "serial"): ["show version | include Serial Number"],
        ("juniper", "interface"): ["show interfaces terse | match up | match inet"],
        ("cisco", "interface"): ["show ip interface brief | include up"],
        ("huawei", "interface"): ["display ip interface brief | include up"],
        ("extreme", "interface"): ["show ipconfig | include gerencia"]
    }
    return commands.get((manufacturer.lower(), choice), [])

# Função para se conectar e executar os comandos no dispositivo remoto
def connect_and_execute(hostname, username, password, manufacturer, choice):
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, password=password)
        
        commands = get_commands_by_manufacturer(manufacturer, choice)
        if not commands:
            logging.warning(f"Nenhum comando definido para o fabricante {manufacturer} e escolha {choice}.")
            return {}
        
        interface_data = {}  # Dicionário para armazenar as interfaces e IPs

        for command in commands:
            logging.info(f"Executando comando: {command} no dispositivo {hostname}")
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode()
            logging.info(f"Saída do comando no dispositivo {hostname}:\n{output}")

            # Processar as interfaces e IPs a partir do comando executado
            if choice == "interface":
                for line in output.splitlines():
                    if 'up' in line:  # Ajuste conforme o formato real
                        interface_name, ip_address = parse_interface_output(line)
                        interface_data[interface_name] = ip_address

        client.close()
        return interface_data
    except paramiko.SSHException as e:
        logging.error(f"Erro de conexão SSH com o dispositivo {hostname}: {e}")
        return {}
    except Exception as e:
        logging.error(f"Erro ao executar comandos no dispositivo {hostname}: {e}")
        return {}

# Função para analisar a saída do comando de interface (ajustar conforme necessidade)
def parse_interface_output(line: str):
    # Exemplo simples de parsing; ajustar conforme o formato real da saída
    parts = line.split()
    interface_name = parts[0]
    ip_address = parts[1] if len(parts) > 1 else "0.0.0.0"
    return interface_name, ip_address

# Função para atualizar as interfaces no NetBox
def update_netbox_interfaces(nb, device_name: str, interface_data: Dict[str, str]):
    """
    Atualiza as interfaces no NetBox com base nos dados coletados.
    """
    try:
        device = nb.dcim.devices.get(name=device_name)
        if not device:
            logging.warning(f"Dispositivo '{device_name}' não encontrado no NetBox.")
            return

        for interface_name, ip_address in interface_data.items():
            try:
                interface = nb.dcim.interfaces.get(device_id=device.id, name=interface_name)
                if not interface:
                    logging.warning(f"Interface '{interface_name}' não encontrada no dispositivo '{device_name}'.")
                    continue

                # Atualizar ou criar o IP para a interface
                existing_ips = nb.ipam.ip_addresses.filter(interface_id=interface.id)
                if existing_ips:
                    for ip in existing_ips:
                        ip.delete()
                
                ip_data = {
                    "address": ip_address,
                    "status": "active",
                    "assigned_object_id": interface.id,
                    "assigned_object_type": "dcim.interface",
                }
                nb.ipam.ip_addresses.create(ip_data)
                logging.info(f"Interface '{interface_name}' do dispositivo '{device_name}' atualizada com IP '{ip_address}'.")

            except Exception as e:
                logging.error(f"Erro ao atualizar a interface '{interface_name}': {e}") 
    except Exception as e:
        logging.error(f"Erro ao processar o dispositivo '{device_name}': {e}")

# Função principal para interagir com o usuário
def main(choice):
    # Definir URL do NetBox e token da API
    netbox_url = "https://netbox.ger.tche.br/"
    netbox_token = "15bb8d596de8c17fac6a7b6a73579d7cb91e46e5"
    if not netbox_token:
        raise ValueError("Token do NetBox não configurado. Configure a variável de ambiente 'NETBOX_TOKEN'.")

    nb = init_netbox(netbox_url, netbox_token)

    # Carregar informações dos hosts (certifique-se de que o arquivo ou módulo 'hosts_info' está correto)
    from hosts_info import hosts_info  # Certifique-se de que este arquivo existe e está no formato esperado

    for host_key, host_info in hosts_info.items():
        hostname = host_info['hostname']
        username = host_info['username']
        password = host_info['password']
        manufacturer = host_info['manufacturer']

        interface_data = connect_and_execute(hostname, username, password, manufacturer, choice)
        if interface_data:
            update_netbox_interfaces(nb, hostname, interface_data)

if __name__ == "__main__":
    # Função principal para interagir com o usuário
    def main(choice):
        # Definir URL do NetBox e token da API
        netbox_url = "https://netbox.ger.tche.br/"
        netbox_token = "15bb8d596de8c17fac6a7b6a73579d7cb91e46e5"
        if not netbox_token:
            raise ValueError("Token do NetBox não configurado. Configure a variável de ambiente 'NETBOX_TOKEN'.")

        # Inicializar a conexão com o NetBox
        nb = init_netbox(netbox_url, netbox_token)

        # Carregar informações dos hosts
        from hosts_info import hosts_info  # Certifique-se de que este arquivo existe e está no formato esperado

        for host_key, host_info in hosts_info.items():
            hostname = host_info['hostname']
            username = host_info['username']
            password = host_info['password']
            manufacturer = host_info['manufacturer']

            try:
                # Coletar dados de interface via SSH
                interface_data = connect_and_execute(hostname, username, password, manufacturer, choice)
                if interface_data:
                    for interface_name, ip_address in interface_data.items():
                        try:
                            # Buscar a interface no NetBox
                            interface = nb.dcim.interfaces.get(device_id=host_info.get("device_id"), name=interface_name)
                            if not interface:
                                logging.warning(
                                    f"Interface '{interface_name}' não encontrada no dispositivo '{hostname}'."
                                )
                                continue

                            # Atualizar ou criar o IP para a interface
                            existing_ips = nb.ipam.ip_addresses.filter(interface_id=interface.id)
                            if existing_ips:
                                for ip in existing_ips:
                                    ip.delete()

                            ip_data = {
                                "address": ip_address,
                                "status": "active",
                                "assigned_object_id": interface.id,
                                "assigned_object_type": "dcim.interface",
                            }
                            nb.ipam.ip_addresses.create(ip_data)
                            logging.info(
                                f"Interface '{interface_name}' do dispositivo '{hostname}' atualizada com IP '{ip_address}'."
                            )
                        except Exception as e:
                            logging.error(f"Erro ao atualizar a interface '{interface_name}': {e}")

            except Exception as e:
                logging.error(f"Erro ao processar o dispositivo '{hostname}': {e}")

    # Solicitação de entrada do usuário
    choice = input("Escolha o tipo de comando ('serial' ou 'interface'): ").strip().lower()
    if choice not in ["serial", "interface"]:
        logging.error("Escolha inválida! Por favor, digite 'serial' ou 'interface'.")
    else:
        main(choice)