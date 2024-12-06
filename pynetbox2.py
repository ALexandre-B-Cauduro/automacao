import pynetbox
import urllib3
from pydantic import BaseModel
from typing import ClassVar

class Primary_IP4(BaseModel):
   id: int
   family: int 
   address: str 
   
   def serializer_model(self) -> int:
       return self.id

def init_netbox(url: str, token: str) -> pynetbox.core.api.Api:
   nb = pynetbox.api(url, token)
   nb.http_session.verify = False
   urllib3.disable_warnings()
   return nb

class Device(BaseModel):
   api_url: ClassVar[str] = "https://netbox/"
   token: ClassVar[str] = "xxxxxxxxxxxxxxxxxxxxxx"
   nb: ClassVar[pynetbox.core.api.Api] = init_netbox(api_url, token)

   def update_serial(self, device_id: int, new_serial: str) -> bool:
       # Obtém o dispositivo pelo ID
       device = self.nb.dcim.devices.get(device_id)
       if device:
           # Atualiza o número de série
           device.serial = new_serial
           device.save()
           return True
       return False

def update_multiple_devices(device_ids: list[int], new_serials: list[str]) -> None:
   device_instance = Device()

   for i, device_id in enumerate(device_ids):
       new_serial = new_serials[i] if i < len(new_serials) else new_serials[-1]
       success = device_instance.update_serial(device_id, new_serial)
       if success:
           print(f"Dispositivo ID {device_id} atualizado com sucesso.")

if __name__ == "__main__":
   device_ids = [181, 175, 176]  
   new_serials = ['BU0914AK0173', 'BU0615AK0089', 'BU0615AK0015'] 

   update_multiple_devices(device_ids, new_serials)
