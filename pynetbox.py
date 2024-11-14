import pynetbox
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# Ignora avisos de certificado
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# Conexão com a API do NetBox
nb = pynetbox.api(
   'https://netbox.ger.tche.br/',   # URL do NetBox
   token='15bb8d596de8c17fac6a7b6a73579d7cb91e46e5'         # Token de autenticação
)

nb.http_session.verify = False # Desativa verificação SSL

# Parâmetros da atualização
device_name = "INSTITUIÇÃO"
interfaces_ips = {
   "ge-0/0/0": "xxx.xxx.xxx.xxx/xx",
   "ge-0/0/1": "xxx.xxx.xxx.xxx/xx", 
   }

try:
   # Localizar o dispositivo pelo nome
   device = nb.dcim.devices.get(name=device_name)
   if device is None:
       raise ValueError(f"Dispositivo '{device_name}' não encontrado.")
   
   # Iterar sobre cada interface e IP
   for interface_name, novo_ip in interfaces_ips.items():
       try:
           # Localizar a interface do dispositivo pelo nome
           interface = nb.dcim.interfaces.get(device_id=device.id, name=interface_name)
           if interface is None:
               print(f"Interface '{interface_name}' não encontrada no dispositivo '{device_name}'. Pulando para a próxima.")
               continue

           # Remover IP existente (se houver)
           existing_ip = nb.ipam.ip_addresses.filter(interface_id=interface.id)
           if existing_ip:
               existing_ip[0].delete()

           # Adicionar o novo IP à interface
           ip_data = {
               "address": novo_ip,
               "status": "active",
               "assigned_object_id": interface.id,
               "assigned_object_type": "dcim.interface",
           }
           new_ip = nb.ipam.ip_addresses.create(ip_data)
           print(f"IP atualizado para {novo_ip} na interface '{interface_name}' do dispositivo '{device_name}'.")

       except Exception as e:
           print(f"Erro ao atualizar o IP na interface '{interface_name}': {e}")

except Exception as e:
   print(f"Erro ao processar o dispositivo '{device_name}': {e}")