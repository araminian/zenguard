from typing import Union
from kubernetes import client

def patchConfigMap(configMapName: str,namespace: str,newData: dict)-> Union[bool,dict]:

    v1API = client.CoreV1Api()
    body=client.V1ConfigMap(api_version='v1',kind='ConfigMap',data=newData)
    try:
        v1API.patch_namespaced_config_map(
            name=configMapName,
            namespace=namespace,
            body=body
        )
    except client.exceptions.ApiException as e:
        return {"ErrorCode":'601',"ErrorMsg": "Can not patch configMap {0} , reason {1}".format(configMapName,e.reason)}
    return True

def patchDeployment(deploymentName:str,namepsace:str,newBody:client.V1Deployment)->Union[dict,bool]:

    appsV1 = client.AppsV1Api()

    try:
        appsV1.patch_namespaced_deployment(
    name=deploymentName,
    namespace=namepsace,
    body=newBody
    )
    except client.exceptions.ApiException as e:
        return {"ErrorCode":"601","ErrorMsg": "Can not patch deployment {0}".format(deploymentName)}
    
    return True
