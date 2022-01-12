from pydantic import BaseModel, StrictInt, ValidationError, validator , IPvAnyNetwork , IPvAnyAddress
import base64 , binascii
from typing import List, Optional
import ipaddr
from pathlib import Path


class KeyModel(BaseModel):
    Key : bytes

    @validator('Key')
    def check_base64(cls,v):
        try:
            base64.decodebytes(v)
            return v.decode()
        except binascii.Error:
            raise ValueError('The Key should be in Base64 Format')

class InterfaceModel(BaseModel):

    PrivateKey : KeyModel
    ListenPort : Optional [StrictInt]
    CommentKey: Optional[str]
    CommentValue : Optional[str]
    Address: Optional [str]

    @validator('ListenPort')
    def check_ephemeral_ports(cls,v):
        if not 49152 <= v <= 65535:
            raise ValueError('Listen port should be in range of epemeral 49152 to 65535')
        return v

class EndpointModel(BaseModel):
    Address: Optional [IPvAnyAddress] = None
    Port: StrictInt
    Hostname: Optional [str] = None

    @validator('Address')
    def check_IP(cls,v):
        version = ipaddr.IPAddress(v).version
        if(version == 4):
            return "{0}".format(v)
        else:
            return "[{0}]".format(v)
    
    @validator('Port')
    def check_port_range(cls,v):
        if not 0 <= v <= 65535:
            raise ValueError('Listen port should be in range of 0 to 65535')
        return v


class PeerModel(BaseModel):

    PublicKey : KeyModel
    PreSharedKey: Optional[KeyModel]
    AllowedIPs: List[IPvAnyNetwork]
    Endpoint: Optional[EndpointModel] = None
    CommentKey: Optional[str]
    CommentValue : Optional[str]

    @validator('AllowedIPs',each_item=True)
    def return_str(cls,v):
        return "{0}".format(v)

class ConfigComponentsModel(BaseModel):
    Interface : dict
    Peers : List[dict]
    ConfigPath : str

    @validator('ConfigPath')
    def is_dir(cls,v):
        path = Path(v)
        if(not path.is_file):
            raise ValueError('Configuration Path should not be Dir.')
        return v