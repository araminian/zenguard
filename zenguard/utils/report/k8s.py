from kubernetes import client
from typing import Union

def readSecret(secretName: str,namespace: str)-> dict:
    v1API = client.CoreV1Api()
    try:
        secret = v1API.read_namespaced_secret(
            name=secretName,
            namespace=namespace
        )
    except client.exceptions.ApiException as e:
        return {"ErrorCode":'600',"ErrorMsg": "Can not read secret {0} , reason {1}".format(secretName,e.reason)}
    
    return secret.data


def readConfigMap(configMapName: str,namespace: str)-> dict:
    v1API = client.CoreV1Api()
    try:
        configMap = v1API.read_namespaced_config_map(
            name=configMapName,
            namespace=namespace
        )
    except client.exceptions.ApiException as e:
        return {"ErrorCode":'600',"ErrorMsg": "Can not read configMap {0} , reason {1}".format(configMapName,e.reason)}
    
    return configMap.data


def getLoadBalancerIP(loadBalancerName: str,namespace: str) -> Union[str,dict]:
    v1API = client.CoreV1Api()
    try:
        lb = v1API.read_namespaced_service(
            name= loadBalancerName,
            namespace=namespace
        )
    except client.exceptions.ApiException as e:
        return {"ErrorCode":'600',"ErrorMsg": "Can not read loadbalancer {0} , reason {1}".format(loadBalancerName,e.reason)}
    
    return str(lb.status.load_balancer.ingress[0].ip)
