from kubernetes import client
from typing import Union

def deleteConfigMap(name:str,namespace:str) -> Union[bool,dict]:
    v1API = client.CoreV1Api()
    try:
        v1API.delete_namespaced_config_map(
            name=name,
            namespace=namespace
        )
        
    except client.exceptions.ApiException as e:
        return {"ErrorCode":'602',"ErrorMsg": "Can not delete configMap {0} , reason {1}".format(name,e.reason)}
    
    return True
