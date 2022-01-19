from kubernetes import client

def findConfgMapByLabel(namespace:str,label_selector:dict) -> dict:

    v1API = client.CoreV1Api()

    try:
        configMaps = v1API.list_namespaced_config_map(
            namespace=namespace,
            label_selector=label_selector
        )

        configMapsDict = {}
        for cm in configMaps.items:
            configMapsDict[cm.metadata.name] = cm
        
        return configMapsDict

    except client.exceptions.ApiException as e:
        return {"ErrorCode":'603',"ErrorMsg": "Can not find configMaps based on this label selector {0} , reason {1}".format(label_selector,e.reason)}