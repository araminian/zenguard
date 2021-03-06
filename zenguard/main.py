
from re import template
from kopf._core.actions.execution import no_extra_context
from kubernetes.client.models.v1_capabilities import V1Capabilities
from kubernetes.client.models.v1_config_map_volume_source import V1ConfigMapVolumeSource
from kubernetes.client.models.v1_security_context import V1SecurityContext
from pymongo import server
from zenguard.utils.report.network import *
from zenguard.utils.report.k8s import *
from zenguard.utils.nacl.IPUtils import *
import kopf
from kubernetes import client
from kubernetes.client.rest import ApiException
from zenguard.utils.nacl.security import *
from zenguard.utils.report.network import *
from zenguard.utils.k8s.update import *
import tempfile
from zenguard.utils.wireguard.generator import clientGenerate, serverGenerate
from pathlib import Path

@kopf.on.create('wgnetworks.zenguard.io')
def create_wgnetwork_fn(spec, name, namespace, logger, **kwargs):

    # ------------------------------- General -------------------------------------------
    notMandatorySectionSet = False
    networkSpec = spec.get('network')
    if not networkSpec:
        logger.error('Network settings must be set')
        notMandatorySectionSet = True
    serverSpec = spec.get('server')
    if not serverSpec:
        logger.error('Server settings must be set')
        notMandatorySectionSet = True
    serviceSpec = spec.get('service')
    if not serviceSpec:
        logger.error('Service settings must be set')
        notMandatorySectionSet = True
    
    if 'CIDR' not in networkSpec:
        logger.error("CIDR must be set")
        notMandatorySectionSet = True

    if 'IPAddress' not in serverSpec:
        logger.error("Server IP must be set")
        notMandatorySectionSet = True
    
    if 'port' not in serverSpec:
        logger.error("Server port must be set")
        notMandatorySectionSet = True
    
    if 'type' not in serviceSpec:
        logger.error("Service type must be set")
        notMandatorySectionSet = True

    if (notMandatorySectionSet):
        raise kopf.PermanentError('Mandatory settings must be set')

    
    # ------------------------------- Network -------------------------------------------
    
    CIDR = networkSpec['CIDR']

        
    # Check Valid CIDR
    Linter = False
    validCIDR = isValidCIDR(CIDR=CIDR)
    if(type(validCIDR) == dict and 'ErrorMsg' in validCIDR):
        logger.error(validCIDR['ErrorMsg'])
        Linter = True
    
    # Check Reserved Range
    
    if ('reservedRange' in networkSpec):
        reservedRange = networkSpec['reservedRange']
        rangeParts = reservedRange.split('-')
        ## Check ReservedRange in a good format 'Start-End'
        if (len(rangeParts) != 2):
            Linter = True
            logger.error("Invalid ReservedRange format '{0}'".format(reservedRange))
            raise kopf.PermanentError("Invalid ReservedRange format '{0}'".format(reservedRange))

        ## Check start of range is Valid IP
        startValid = False
        endValid = False
        isStartRangeValid = isValidIP(IP=rangeParts[0])
        if (type(isStartRangeValid) == dict and 'ErrorMsg' in isStartRangeValid ):
            logger.error("The start IP '{0}' of ReservedRange is not valid IP Address".format(rangeParts[0]))
            Linter = True
        else:
            ## Check start of range inside CIDR
            startValid = True
            isStartRangeInCIDR = isIPinCIDR(CIDR=CIDR,IP=rangeParts[0])
            if (not isStartRangeInCIDR):
                logger.error("The start '{0}' of ReservedRange is not inside of CIDR '{1}".format(rangeParts[0],CIDR))
                Linter = True

        ## Check end of range is Valid IP
        isEndRangeValid = isValidIP(IP=rangeParts[1])
        if(type(isEndRangeValid) == dict and 'ErrorMsg' in isEndRangeValid):
            logger.error("The end IP '{0}' of ReservedRange is not valid IP Address".format(rangeParts[0]))
            Linter = True
        else:
            ## Check end of range inside CIDR
            endValid = True
            isEndRangeInCIDR = isIPinCIDR(CIDR=CIDR,IP=rangeParts[1])
            if (not isEndRangeInCIDR):
                logger.error("The end '{0}' of ReservedRange is not inside of the CIDR '{1}'".format(rangeParts[1],CIDR))
                Linter = True
        
        ## Check start of range smaller than end of range
        if (startValid and endValid):
            if (not isIPSmallerThan(smallIP=rangeParts[0],bigIP=rangeParts[1])):
                logger.error("The start '{0}' of ReservedRange is bigger than end '{1}' of ReservedRange".format(rangeParts[0],rangeParts[1]))
                Linter = True

    

    if('reservedIPs' in networkSpec):
        reservedIPs = networkSpec['reservedIPs']
        # Check the Reserved IPs are Valid

        for ip in reservedIPs:
            
            isIPValid = isValidIP(IP=ip)
            if (type(isIPValid) == dict and 'ErrorMsg' in isIPValid):
                logger.error("The Reserved IP '{0}' is not valid IP Address".format(ip))
                Linter = True
            else:
                # Check the IP is in the CIDR
                isIPInside = isIPinCIDR(CIDR=CIDR,IP=ip)
                if(not isIPInside):
                    logger.error("The Reserved IP '{0}' is not inside of the CIDR '{1}'".format(ip,CIDR))
                    Linter = True
        reservedIPs.append(serverSpec['IPAddress'])
    else:
        reservedIPs = []
        reservedIPs.append(serverSpec['IPAddress'])
    # ------------------------------- Server -------------------------------------------
    
    ## Check Server IP is Valid
    serverIP = serverSpec['IPAddress']
    isServerIPValid = isValidIP(IP=serverIP)
    if (type(isServerIPValid) == dict and 'ErrorMsg' in isServerIPValid ):
        logger.error("The server IP '{0}' is not valid IP Address".format(serverIP))
        Linter = True
    else:
        # Check the IP is in the CIDR
        isIPInside = isIPinCIDR(CIDR=CIDR,IP=serverIP)
        if(not isIPInside):
            logger.error("The server IP '{0}' is not inside of the CIDR '{1}'".format(serverIP,CIDR))
            Linter = True
    
    ## Check port
    serverPort = serverSpec['port']
    if(not isinstance(serverPort,int) or serverPort <= 0 or serverPort > 65535):
        logger.error("The server port '{0}' is not valid port number".format(serverPort))
        Linter = True
    
    ## Check route
    if('additionalRoutes' in serverSpec):
        serverAdditionalRoute = serverSpec['additionalRoutes']
        for route in serverAdditionalRoute.split(','):
            isRouteValid = isValidCIDR(CIDR=route)
            if(type(isRouteValid) == dict and 'ErrorMsg' in isRouteValid):
                logger.error(isRouteValid['ErrorMsg'])
                Linter = True
    
    ## Check resources
    if('resources' in serverSpec):
        serverResources = serverSpec['resources']
        if ('limits' not in serverResources and 'requests' not in serverResources):
            logger.error("Limits or requests should be set in the server resources")
            Linter = True
        if ('limits' in serverResources):
            if ('cpu' not in serverResources['limits'] and 'memory' not in serverResources['limits']):
                logger.error("CPU or memory should be specified for limits in the server resources")
                Linter = True
        if ('requests' in serverResources):
            if ('cpu' not in serverResources['requests'] and 'memory' not in serverResources['requests']):
                logger.error("CPU or memory should be specified for requests in the server resources")
                Linter = True
    
    ## Secert
    # TODO: Secret check 

    ## injectPodCIDR
    if ('injectPodCIDR' in serverSpec):
        serverInjectPodCIDR = serverSpec['injectPodCIDR']
        if(not isinstance(serverInjectPodCIDR,bool)):
            logger.error("injectPodCIDR setting in server must be boolean")
            Linter = True
    

    # ------------------------------- Service -------------------------------------------

    serviceType = serviceSpec['type']

    validServiceTypes = ['NodePort','LoadBalancer','ClusterIP']
    if(serviceType not in validServiceTypes):
        logger.error("Invalid service type '{0}'. It should be '{1}".format(serviceType,' '.join(validServiceTypes)))
        Linter = True
    
    if((serviceType == 'NodePort' or serviceType == 'LoadBalancer') and 'port' in serviceSpec):
        if(not isinstance(serviceSpec['port'],int) or serviceSpec['port'] <= 0 or serviceSpec['port'] > 65535):
            logger.error("The service port '{0}' is not valid port number".format(serviceSpec['port']))
            Linter = True
    if(serviceType == 'NodePort' and 'nodeAddress' not in serviceSpec):
        logger.error("The node address must be specified when NodePort is used")
        Linter = True
    # ------------------------------- Lint Finish -------------------------------------------

    if(Linter):
        raise kopf.PermanentError('Lint failed')


    network = "{0}-{1}".format(name,namespace)
    # ------------------- Server setup ---------------------------------------
    v1API = client.CoreV1Api()
    ## Server Key
    serverKeys = None
    if 'secret' not in serverSpec:
        serverKeys=generateEDKeyPairs()
    
    ## Routes
    ### Inject CIDR
    serverRouteLists = []
    serverRouteLists.append(CIDR)
    ### Inject Addtional Routes
    if ('additionalRoutes' in serverSpec):
        serverRouteLists.append(serverSpec['additionalRoutes'])
    ### Inject Pod CIDR
    if ('injectPodCIDR' in serverSpec and serverSpec['injectPodCIDR']):
        try:
            nodes=v1API.list_node()
            serverRouteLists.append(nodes.items[0].spec.pod_cidr)
        except client.exceptions.ApiException as e:
            raise kopf.PermanentError(e.reason)
            
    serverInfo = {

        '_id': get_sha2("server-{0}".format(network)),
        'IPAddress': serverSpec['IPAddress'],
        'port': str(serverSpec['port']),
        'privateKey': serverKeys[0],
        'publicKey': serverKeys[1],
        'injectPodCidr': str(serverSpec['injectPodCIDR']),
        'routes': ','.join(serverRouteLists),
        'CIDR': str(CIDR),
        'wgRevision': "1"
    }

    ## Create a Secret for Server Key Pairs

    serverSecretMetadata = client.V1ObjectMeta(
        namespace=namespace,
        name="zg-serverkeys-{0}".format(name),
        labels={
            'manager': 'zenguard',
            'network': name,
            'type': 'keys',
            'usedBy': 'server'
        })
    serverKeysData = {"privateKey":serverInfo['privateKey'],"publicKey":serverInfo['publicKey']}
    serverSecretObject = client.V1Secret(api_version='v1',kind='Secret',metadata=serverSecretMetadata,type='Opaque',data=serverKeysData)
    kopf.adopt(serverSecretObject)
    try:
        v1API.create_namespaced_secret(namespace=namespace,body=serverSecretObject)
    except client.exceptions.ApiException as e:
        logger.error("Could not create server keys secret")
        raise kopf.PermanentError(e.reason)

    
    ## Server WireGuard ConfigMap
    subnet = {}
    subnet['mask'] = str(IPNetwork(CIDR).netmask)
    wgConfigTempDir = tempfile.TemporaryDirectory(dir="/tmp")
    serverGenerate(clients=[],server=serverInfo,subnet=subnet,outputDir=wgConfigTempDir.name,networkName=network)
    wgServerConfigPath = "{0}/wg-server.conf".format(wgConfigTempDir.name)
    if not Path(wgServerConfigPath).is_file():
        raise kopf.PermanentError("Server WireGuard configuration file could not be generated")
    wgServerConfig = open(wgServerConfigPath, "r")

    wgRevision = "1"
    wgServerConfigMapMetadata = client.V1ObjectMeta(
        namespace=namespace,
        name = "zg-wg-{0}-{1}".format(name,wgRevision),
        labels={
            'manager': 'zenguard',
            'network': name,
            'type': 'wgConfig',
            'usedBy': 'server',
            'version': '1'
        }
    )
    wgServerConfigurationData = {'wg0.conf': wgServerConfig.read() }
    wgServerConfigMapObject = client.V1ConfigMap(
        api_version='v1',kind='ConfigMap',data=wgServerConfigurationData,metadata=wgServerConfigMapMetadata
    )

    try:
        serverConfigMapManifest = v1API.create_namespaced_config_map(namespace=namespace,body=wgServerConfigMapObject)
    except client.exceptions.ApiException as e:
        logger.error("Could not create server wireguard configuration configMap")
        raise kopf.PermanentError(e.reason)
    wgConfigTempDir.cleanup()


    ## Create Server Deployment

    serverDeploymentMetadata = client.V1ObjectMeta(
        namespace=namespace,
        name = "zg-{0}-server".format(name),
        labels={
            'manager': 'zenguard',
            'network': name,
        }
    )
    serverContainerConfigMapVolume = client.V1Volume(
        name='wg',
        config_map=V1ConfigMapVolumeSource(
            name="zg-wg-{0}-{1}".format(name,wgRevision)
        )
    )

    serverContainerVolumeMount = client.V1VolumeMount(name='wg',mount_path='/etc/wireguard')
    serverContainerResources = None
    if ('resources' in serverSpec):
        serverContainerResourcesLimits = None
        serverContainerResourcesRequests = None
        if('limits' in serverSpec['resources']):
            serverContainerResourcesLimits = serverSpec['resources']['limits']
        if ('requests' in serverSpec['resources']):
            serverContainerResourcesRequests = serverSpec['resources']['requests']
        serverContainerResources = client.V1ResourceRequirements(
            limits=serverContainerResourcesLimits,
            requests=serverContainerResourcesRequests
        )
    serverContainer = client.V1Container(
        name='wireguard',
        image='heiran/wireguard',
        image_pull_policy='Always',
        volume_mounts= [serverContainerVolumeMount],
        resources= serverContainerResources,
        ports=[client.V1ContainerPort(container_port=serverSpec['port'],protocol='UDP')],
        command= ["/bin/bash","-c","--"],
        args=["wg-quick up wg0 && while true; do sleep 30; done;"],
        security_context= client.V1SecurityContext(
            capabilities= client.V1Capabilities(
                add = ["NET_ADMIN","SYS_MODULE"]
            )
        )
    )

    serverPodTemplate = client.V1PodTemplateSpec(
        metadata= client.V1ObjectMeta(
            labels= {
                'manager': 'zenguard',
                'network': name
            }
        ),
        spec=client.V1PodSpec(
            containers=[serverContainer],
            volumes=[serverContainerConfigMapVolume]
        )
    )

    serverDeploymentSpec = client.V1DeploymentSpec(
        replicas=1,
        template=serverPodTemplate,
        selector= {
            "matchLabels":{
                'manager': 'zenguard',
                'network': name
            }
        }
    )

    serverDeployment = client.V1Deployment(
        api_version="apps/v1",
        kind="Deployment",
        metadata=serverDeploymentMetadata,
        spec=serverDeploymentSpec,
    )

    kopf.adopt(serverDeployment)

    try:
        appsV1 = client.AppsV1Api()
        appsV1.create_namespaced_deployment(
            namespace=namespace,
            body=serverDeployment
        )   
    except client.exceptions.ApiException as e:
        logger.error("Could not deploy server as deployment")
        raise kopf.PermanentError(e.reason)


    # --------------------Service Setup---------------------------------------

    serviceObjectMetadata = client.V1ObjectMeta(
        name="zg-wg-{0}".format(name),
        labels= {
                'manager': 'zenguard',
                'network': name
            }
    )

    if (serviceSpec['type']=='NodePort' and 'port' in serviceSpec):

        serviceObjectPort = client.V1ServicePort(
                protocol='UDP',
                target_port=serverSpec['port'],
                port=serverSpec['port'],
                node_port=serviceSpec['port']
            )
    else:
        serviceObjectPort = client.V1ServicePort(
                protocol='UDP',
                target_port=serverSpec['port'],
                port=serverSpec['port']
            )
    

    
    serviceObjectSpec = client.V1ServiceSpec(
            type=serviceSpec['type'],
            selector= {
                'manager': 'zenguard',
                'network': name
        },
            ports= [serviceObjectPort]   
        )
    
    serviceObject = client.V1Service(
        metadata=serviceObjectMetadata,
        spec=serviceObjectSpec  
    )

    kopf.adopt(serviceObject)

    try:
        serviceObjectResponse = v1API.create_namespaced_service(
            namespace=namespace,
            body=serviceObject
        )   
    except client.exceptions.ApiException as e:
        logger.error("Could not create service")
        raise kopf.PermanentError(e.reason)

    # ------------------------------ Create Server ConfigMap --------------------------
    serverConfigMapMetadata = client.V1ObjectMeta(
        namespace=namespace,
        name="zg-serverconfigs-{0}".format(name),
        labels={
            'manager': 'zenguard',
            'network': name,
            'type': 'configs',
            'usedBy': 'server'
        }
    )
    serverConfigs = serverInfo.copy()
    serverConfigs.pop('privateKey')
    serverConfigs.pop('publicKey')
    serverConfigs.pop('_id')
    
    serverConfigs['serviceType'] = serviceSpec['type']

    if (serviceSpec['type'] == 'NodePort'):
        serverConfigs['nodePort'] = str(serviceObjectResponse.spec.ports[0].node_port)
        serverConfigs['publicIPAddress'] = serviceSpec['nodeAddress']
    if (serviceSpec['type'] == 'ClusterIP'):
        serverConfigs['publicIPAddress'] = str(serviceObjectResponse.spec.cluster_ip)
    
    serverConfigMapObject = client.V1ConfigMap(
        api_version='v1',kind='ConfigMap',data=serverConfigs,metadata=serverConfigMapMetadata
    )

    kopf.adopt(serverConfigMapObject)
    try:
        v1API.create_namespaced_config_map(namespace=namespace,body=serverConfigMapObject)
    except client.exceptions.ApiException as e:
        logger.error("Could not create server configuration configMap")
        raise kopf.PermanentError(e.reason)
    

    # ------------------- Network setup --------------------------------------

    initialResult = initializeSubnet(
        Network=network,
        CIDR=CIDR,
        ReservedRange=reservedRange,
        ReservedIPs=reservedIPs
    )

    if(type(initialResult) == dict and 'ErrorMsg' in initialResult):
        logger.error(initialResult['ErrorMsg'])
        raise kopf.TemporaryError('Network initialization failed')
    
    if(initialResult == True):
        logger.info('Network initialization done')

    # Reserve and request Server IP
    requestIP(
        Network=network,
        clientName='Server',
        IP=serverSpec['IPAddress']
    )

@kopf.on.create('wgclients.zenguard.io')
def create_wgclient_fn(spec, name, namespace, logger, **kwargs):

    network = spec.get('network')

    if not network:
        logger.error('Network must be set')
        raise kopf.PermanentError('Network must be set and is mandatory.')
    
    networkNamespace = "{0}-{1}".format(network,namespace)
    Linter = False

    # Check if the network exists
    isInitialized = isNetworkInitialized(Network=networkNamespace)

    if (type(isInitialized) == dict):
        logger.error("ERROR: {0}".format(isInitialized['ErrorMsg']))
        raise kopf.PermanentError('Lint failed')
    if (type(isInitialized) == tuple and not isInitialized[0]):
        logger.error("ERROR: The network {0} is not initialized".format(network))
        raise kopf.PermanentError('Lint failed')
    
    # Check client IP
    ip = spec.get('IPAddress')

    subnetInfo = get_all_entries(database_name=networkNamespace,table_name='subnet')
    if(type(subnetInfo) == dict and 'ErrorMsg' in subnetInfo):
        logger.error(subnetInfo['ErrorMsg'])
        raise kopf.PermanentError("Can't access database")

    subnetInfo = list(subnetInfo['Enteries'])[0]
    subnetReport = getNetworkReport(networkNamespace)
    if ip:
       if subnetReport['NumFreeStaticIPs'] == 0:
           raise kopf.PermanentError("Not enough reserved IP address to assign")
    else:
       if subnetReport['NumFreeNonStaticIPs'] == 0:
           raise kopf.PermanentError("Not enough IP address to assign")

    if ip:
    ## Check IP is valid
        IPValid = isValidIP(IP=ip)
        if(type(IPValid) == dict and 'ErrorMsg' in IPValid):
            logger.error("The IP '{0}' is not valid IP Address".format(ip))
            Linter = True
        else:
            
            IPisInReservedRange = True
            IPisInReservedIPs = True
            ### Check if IP is in Reserved Range
            if('reservedRange' in subnetInfo):
                reservedRange = subnetInfo['reservedRange'].split('-')
                ipInRange = isIPinRange(range=reservedRange,IP=ip)
                if (not ipInRange):
                    IPisInReservedRange = False

            ### Check if IP is in Reserved IPs
            if('reservedIPs' in subnetInfo):
                reservedIPs = subnetInfo['reservedIPs'].split(',')
                if(ip not in reservedIPs):
                    IPisInReservedIPs = False

            if(not IPisInReservedIPs and not IPisInReservedRange):
                Linter = True
                logger.error("The IP '{0}' is not in the reserved range or reserved IPs".format(ip))
            

    if(Linter):
        raise kopf.PermanentError('Lint failed')
    

    # ---------------------- Get an IP address for the Client ---------------------------
    requestedIP = requestIP(
        Network=networkNamespace,
        clientName=name,
        IP=ip
    )
    
    if(type(requestedIP) == dict):
        logger.error("ERROR : {0}".format(requestedIP['ErrorMsg']))    
        raise kopf.PermanentError("Can't request IP for client")
    # --------------------- Read zg-serverconfigs-[net] configmap ----------------------
    
    serverConfigs = readConfigMap(
        configMapName="zg-serverconfigs-{0}".format(network),
        namespace=namespace
    )

    if ('ErrorCode' in serverConfigs):
        returnIP(Network=networkNamespace,clientName=name)
        raise kopf.TemporaryError(serverConfigs['ErrorMsg'])
    
    # ---------------------Specify Client route---------------------------

    clientRoute = serverConfigs['routes']
    routesSpec = spec.get('routes')
    additionalRoutesSpec = spec.get('additionalRoutes')
    ## routeSpec has more priority
    if (additionalRoutesSpec):
        clientRoute = "{0},{1}".format(serverConfigs['routes'],additionalRoutesSpec)
    if (routesSpec):
        clientRoute = routesSpec
    # ----------------------Handle Client Secret -----------------------------

    clientKeys = None
    if ('secret' not in spec):
        clientKeys = generateEDKeyPairs()
    # TODO: Implement Secret

    # --------------------- Client Info ---------------------------------------

    clientInfo = {
        "_id": get_sha2(name),
        "name": name,
        "privateKey": clientKeys[0],
        "publicKey" : clientKeys[1],
        "IPAddress" : requestedIP,
        "routes" : clientRoute

    }

    # -------------------- Create Server and Subnet dicts for generate WG configs ---------------------------------

    ## Read Server Secret
    serverKeys = readSecret(
        secretName="zg-serverkeys-{0}".format(network),
        namespace=namespace
    )

    if ('ErrorCode' in serverKeys):
        returnIP(Network=networkNamespace,clientName=name)
        raise kopf.TemporaryError(serverKeys['ErrorMsg'])

    ## Server Public IP Address
    if ( serverConfigs['serviceType'] == 'LoadBalancer'):
        serverPublicIP = getLoadBalancerIP(
            loadBalancerName="zg-wg-{0}".format(network),
            namespace=namespace
        )
        if ('ErrorCode' in serverPublicIP):
            returnIP(Network=networkNamespace,clientName=name)
            raise kopf.TemporaryError(serverPublicIP['ErrorMsg'])
    else:
        serverPublicIP = serverConfigs['publicIPAddress']
    
    ## Server Port
    serverPort = serverConfigs['port']
    if ( serverConfigs['serviceType'] == 'NodePort'):
        serverPort = serverConfigs['nodePort']

    ## SubnetInfo
    subnet = {}
    subnet['mask'] = str(IPNetwork(serverConfigs['CIDR']).netmask)

    ## ServerInfo for generating client wg config
    serverInfoWGClient = {
        'publicKey': serverKeys['publicKey'],
        'publicIPAddress': serverPublicIP,
        'port': serverPort
    }

    ## ServerInfo for generating server wg config
    serverInfoWGServer = {
        'IPAddress': serverConfigs['IPAddress'],
        'port': serverConfigs['port'],
        'privateKey': serverKeys['privateKey']
    }

    # -------------------- Add client info to Database ---------------------------------------
    clientAddResult = add_entry_one(database_name=networkNamespace,table_name='clients',data=clientInfo)

    if(type(clientAddResult) == dict and 'ErrorMsg' in clientAddResult):
        raise kopf.PermanentError(clientAddResult['ErrorMsg'])

    # -------------------- Client Information for generationg Server and client wg configs -------------------

    clientInfoWGClient = {
        'name': name,
        'privateKey': clientKeys[0],
        'IPAddress': requestedIP,
        'routes': clientRoute
    }

    clientsInfoWGServer = getClients(networkNamespace)
    if(type(clientsInfoWGServer) == dict and 'ErrorMsg' in clientsInfoWGServer):
        raise kopf.PermanentError(clientsInfoWGServer['ErrorMsg'])
    
    # ------------------------ Generate WG Configs --------------------------------------

    wgRevision = int(serverConfigs['wgRevision'])
    updateWGRevition = wgRevision + 1

    wgConfigTempDir = tempfile.TemporaryDirectory(dir="/tmp")

    ## Generate Server WG Configs
    serverGenerate(clients=clientsInfoWGServer,server=serverInfoWGServer,subnet=subnet,outputDir=wgConfigTempDir.name,networkName=network)
    wgServerConfigPath = "{0}/wg-server.conf".format(wgConfigTempDir.name)
    if not Path(wgServerConfigPath).is_file():
        raise kopf.PermanentError("Server WireGuard configuration file could not be generated")
    wgServerConfig = open(wgServerConfigPath, "r")

    ## Generate Server WG Config ConfigMap
    v1API = client.CoreV1Api()
    wgServerConfigMapMetadata = client.V1ObjectMeta(
        namespace=namespace,
        name = "zg-wg-{0}-{1}".format(network,updateWGRevition),
        labels={
            'manager': 'zenguard',
            'network': name,
            'type': 'wgConfig',
            'usedBy': 'server',
            'version': str(updateWGRevition)
        }
    )
    wgServerConfigurationData = {'wg0.conf': wgServerConfig.read() }
    wgServerConfigMapObject = client.V1ConfigMap(
        api_version='v1',kind='ConfigMap',data=wgServerConfigurationData,metadata=wgServerConfigMapMetadata
    )

    try:
        serverConfigMapManifest = v1API.create_namespaced_config_map(namespace=namespace,body=wgServerConfigMapObject)
    except client.exceptions.ApiException as e:
        logger.error("Could not create server wireguard configuration configMap")
        raise kopf.PermanentError(e.reason)
    
    ## Update Server ConfigMaps
    serverConfigs['wgRevision'] = str(updateWGRevition)
    serverConfigPathResult = patchConfigMap(
        configMapName="zg-serverconfigs-{0}".format(network),
        namespace=namespace,
        newData=serverConfigs
    )
    if(type(serverConfigPathResult) == dict):
        raise kopf.PermanentError(serverConfigPathResult['ErrorMsg'])
    

    ## Generate Client WG config
    clientGenerate(clients=[clientInfoWGClient],server=serverInfoWGClient,
    subnet=subnet,outputDir=wgConfigTempDir.name)
    wgClientConfigPath = "{0}/wg-{1}.conf".format(wgConfigTempDir.name,name)
    if not Path(wgClientConfigPath).is_file():
        raise kopf.PermanentError("Client WireGuard configuration file could not be generated")
    wgClientConfig = open(wgClientConfigPath, "r")

    ### Generate client WG ConfigMap

    wgClientConfigMapMetadata = client.V1ObjectMeta(
        namespace=namespace,
        name = "zg-wg-client-{0}".format(name),
        labels={
            'manager': 'zenguard',
            'network': network,
            'type': 'wgConfig',
            'usedBy': 'client',
            'client': name
        }
    )
    wgClientConfigurationData = {'wg0.conf': wgClientConfig.read() }
    wgClientConfigMapObject = client.V1ConfigMap(
        api_version='v1',kind='ConfigMap',data=wgClientConfigurationData,metadata=wgClientConfigMapMetadata
    )

    kopf.adopt(wgClientConfigMapObject)

    try:
        v1API.create_namespaced_config_map(namespace=namespace,body=wgClientConfigMapObject)
    except client.exceptions.ApiException as e:
        logger.error("Could not create server wireguard configuration configMap")
        raise kopf.PermanentError(e.reason)
    

    logger.info("Client WireGuard configuration is generated to ConfigMap zg-wg-client-{0}".format(name))

    # ------------------- Update Server Deployment ---------------------------------

    serverDeployment = getDeploymentObject(
        deploymentName="zg-{0}-server".format(network),
        namespace=namespace
    )

    if(type(serverDeployment) == dict and 'ErrorCode' in serverDeployment):

        raise kopf.PermanentError("Could not get server deployment")
    
    serverDeployment.spec.template.spec.volumes[0].config_map.name = "zg-wg-{0}-{1}".format(network,updateWGRevition)

    patchResult = patchDeployment(
        deploymentName="zg-{0}-server".format(network),
        namespace=namespace,
        newBody=serverDeployment
    )

    if (type(patchResult) == dict and "ErrorCode" in patchResult):
        raise kopf.PermanentError("Could not update server deployment to use new WireGuard configuartion")
    
@kopf.on.delete('wgnetworks.zenguard.io')
def delete_network_fn(spec, name, namespace, logger, **kwargs):

    # -------------------- Delete Network DB and Init entry ---------------------------
    network = "{0}-{1}".format(name,namespace)
    deleteResult = removeNetwork(Network=network)

    if(type(deleteResult) == dict):
        if(deleteResult['ErrorCode'] == '300'):
            pass
        else:
            logger.error(deleteResult['ErrorMsg'])
            raise kopf.TemporaryError(deleteResult['ErrorMsg'])
    
    if(deleteResult == True):
        logger.info("The network '{0}' is removed".format(name))

    # ------------------- Delete WireGuard Configuration ConfigMaps --------------------

    from zenguard.utils.k8s.find import findConfgMapByLabel
    from zenguard.utils.k8s.delete import deleteConfigMap

    label_selector = "manager=zenguard,network={0},type=wgConfig,usedBy=server".format(name)

    configMapsDict = findConfgMapByLabel(
        namespace=namespace,
        label_selector=label_selector
    )

    if ("ErrorCode" in configMapsDict):
        logger.error(configMapsDict['ErrorMsg'])
        return
    
    for cmName,cmObject in configMapsDict.items():
        cmDeleteResult = deleteConfigMap(name=cmName,namespace=namespace)
        if (type(cmDeleteResult) == dict):
            logger.error(cmDeleteResult['ErrorMsg'])

@kopf.on.delete('wgclients.zenguard.io')
def delete_network_fn(spec, name, namespace, logger, **kwargs):

    network = spec.get('network')
    networkNamespace = "{0}-{1}".format(network,namespace)


    # --------------------- Release IP and Remove Client from DB -----------------------

    releaseResult = returnIP(Network=networkNamespace,clientName=name)

    if(type(releaseResult) == dict and 'ErrorMsg' in releaseResult):
        
        logger.error(releaseResult['ErrorMsg'])
        raise kopf.PermanentError("can't be deleted")
    
    if(releaseResult != True):
        raise kopf.PermanentError("Can't be deleted")


    clientID = get_sha2(name)
    findClientQuery = {"_id": clientID}
    deleteResult = delete_abstract_one(database_name=networkNamespace,table_name='clients',query=findClientQuery)
    
    if (type(deleteResult) == dict):
        raise kopf.PermanentError("Can not delete client from the database")

    # --------------------- Read zg-serverconfigs-[net] configmap ----------------------
    serverConfigs = readConfigMap(
        configMapName="zg-serverconfigs-{0}".format(network),
        namespace=namespace
    )

    if ('ErrorCode' in serverConfigs):
        raise kopf.TemporaryError("Can not read zg-serverconfigs-{0} ConfigMap".format(network))
    
    # -------------------- Create Server and Subnet dicts for generate WG configs ---------------------------------

    ## Read Server Secret
    serverKeys = readSecret(
        secretName="zg-serverkeys-{0}".format(network),
        namespace=namespace
    )

    if ('ErrorCode' in serverKeys):
        raise kopf.TemporaryError(serverKeys['ErrorMsg'])

    ## ServerInfo for generating server wg config
    serverInfoWGServer = {
        'IPAddress': serverConfigs['IPAddress'],
        'port': serverConfigs['port'],
        'privateKey': serverKeys['privateKey']
    }

    ## SubnetInfo
    subnet = {}
    subnet['mask'] = str(IPNetwork(serverConfigs['CIDR']).netmask)

    # -------------------- Client Information for generationg Server wg configs -------------------

    clientsInfoWGServer = getClients(networkNamespace)
    if(type(clientsInfoWGServer) == dict and 'ErrorMsg' in clientsInfoWGServer):
        raise kopf.PermanentError(clientsInfoWGServer['ErrorMsg'])
    
    # ------------------------ Generate WG Configs --------------------------------------

    wgRevision = int(serverConfigs['wgRevision'])
    updateWGRevition = wgRevision + 1

    wgConfigTempDir = tempfile.TemporaryDirectory(dir="/tmp")

    ## Generate Server WG Configs
    serverGenerate(clients=clientsInfoWGServer,server=serverInfoWGServer,subnet=subnet,outputDir=wgConfigTempDir.name,networkName=network)
    wgServerConfigPath = "{0}/wg-server.conf".format(wgConfigTempDir.name)
    if not Path(wgServerConfigPath).is_file():
        raise kopf.PermanentError("Server WireGuard configuration file could not be generated")
    wgServerConfig = open(wgServerConfigPath, "r")

    ## Generate Server WG Config ConfigMap
    v1API = client.CoreV1Api()
    wgServerConfigMapMetadata = client.V1ObjectMeta(
        namespace=namespace,
        name = "zg-wg-{0}-{1}".format(network,updateWGRevition),
        labels={
            'manager': 'zenguard',
            'network': name,
            'type': 'wgConfig',
            'usedBy': 'server',
            'version': str(updateWGRevition)
        }
    )
    wgServerConfigurationData = {'wg0.conf': wgServerConfig.read() }
    wgServerConfigMapObject = client.V1ConfigMap(
        api_version='v1',kind='ConfigMap',data=wgServerConfigurationData,metadata=wgServerConfigMapMetadata
    )

    try:
        serverConfigMapManifest = v1API.create_namespaced_config_map(namespace=namespace,body=wgServerConfigMapObject)
    except client.exceptions.ApiException as e:
        logger.error("Could not create server wireguard configuration configMap")
        raise kopf.PermanentError(e.reason)
    
    ## Update Server ConfigMaps
    serverConfigs['wgRevision'] = str(updateWGRevition)
    serverConfigPatchResult = patchConfigMap(
        configMapName="zg-serverconfigs-{0}".format(network),
        namespace=namespace,
        newData=serverConfigs
    )
    if(type(serverConfigPatchResult) == dict):
        raise kopf.PermanentError(serverConfigPatchResult['ErrorMsg'])
    

    # ------------------- Update Server Deployment ---------------------------------

    serverDeployment = getDeploymentObject(
        deploymentName="zg-{0}-server".format(network),
        namespace=namespace
    )

    if(type(serverDeployment) == dict and 'ErrorCode' in serverDeployment):

        raise kopf.PermanentError("Could not get server deployment")
    
    serverDeployment.spec.template.spec.volumes[0].config_map.name = "zg-wg-{0}-{1}".format(network,updateWGRevition)

    patchResult = patchDeployment(
        deploymentName="zg-{0}-server".format(network),
        namespace=namespace,
        newBody=serverDeployment
    )

    if (type(patchResult) == dict and "ErrorCode" in patchResult):
        raise kopf.PermanentError("Could not update server deployment to use new WireGuard configuartion")



@kopf.on.delete('ips.tracerip.io')
def delete_ip_fn(spec, name, namespace, logger, **kwargs):

    network = spec.get('Network')
    
    configMapName = "{0}.tracerip".format(name)

    networkNamespace = "{0}-{1}".format(network,namespace)


    #config.load_kube_config()
    core_v1_api = client.CoreV1Api()

    returnedIP = returnIP(Network=networkNamespace,clientName=name)

    if(type(returnedIP) == dict and 'ErrorMsg' in returnedIP):
        
        logger.error(returnedIP['ErrorMsg'])
        raise kopf.PermanentError("can't be deleted")
    
    if(returnedIP != True):
        raise kopf.PermanentError("Can't be deleted")

    label_selector="Managed-by=tracerIP,Network={0},Client={1}".format(network,name)

    isConfigMapDeleted = False
    try:
        configMapList = core_v1_api.list_namespaced_config_map(namespace=namespace,label_selector=label_selector)
        if(len(configMapList.items) == 0):
            isConfigMapDeleted = True
            logger.info("The ConfigMap {0} was deleted manually".format(configMapName))

    except ApiException as e:
        raise kopf.PermanentError("Can't access k8s API Server: %s\n" % e)

    if(not isConfigMapDeleted):
        try:
            core_v1_api.delete_namespaced_config_map(
                name=configMapName,
                namespace=namespace
            )
        except ApiException as e:
            raise kopf.PermanentError("Can't delete configMap: %s\n" % e)
        
@kopf.on.field('ips.tracerip.io', field='spec.IPAddress')
def ipUpdate(name, old,new,spec,status,logger, namespace, **kwargs):
  
    network = spec.get('Network')
    namespacedNetowrk = "{0}-{1}".format(network,namespace)

    isInitialized = isNetworkInitialized(Network=namespacedNetowrk)

    if (type(isInitialized) == dict):
        logger.error("ERROR: {0}".format(isInitialized['ErrorMsg']))
        raise kopf.PermanentError('Lint failed')
    if (type(isInitialized) == tuple and not isInitialized[0]):
        logger.error("ERROR: The network {0} is not initialized".format(network))
        raise kopf.PermanentError('Lint failed')
    
    currentIP = getClientIP(Network=namespacedNetowrk,Client=name)

    core_v1_api = client.CoreV1Api()

    subnetReport = getNetworkReport(namespacedNetowrk)
    requestedIP = None

    Linter = False
    if (new != None):
        ip = new
        subnetInfo = get_all_entries(database_name=namespacedNetowrk,table_name='subnet')
        if(type(subnetInfo) == dict and 'ErrorMsg' in subnetInfo):
            logger.error(subnetInfo['ErrorMsg'])
            raise kopf.PermanentError("Can't access database")

        subnetInfo = list(subnetInfo['Enteries'])[0]
    # Check IP is valid
        IPValid = isValidIP(IP=ip)
        if(type(IPValid) == dict and 'ErrorMsg' in IPValid):
            logger.error("The IP '{0}' is not valid IP Address".format(ip))
            Linter = True
        else:
            
            IPisInReservedRange = True
            IPisInReservedIPs = True
            # Check if IP is in Reserved Range
            if('reservedRange' in subnetInfo):
                reservedRange = subnetInfo['reservedRange'].split('-')
                ipInRange = isIPinRange(range=reservedRange,IP=ip)
                if (not ipInRange):
                    IPisInReservedRange = False

            # Check if IP is in Reserved IPs
            if('reservedIPs' in subnetInfo):
                reservedIPs = subnetInfo['reservedIPs'].split(',')
                if(ip not in reservedIPs):
                    IPisInReservedIPs = False

            if(not IPisInReservedIPs and not IPisInReservedRange):
                Linter = True
                logger.error("The IP '{0}' is not in the reserved range or reserved IPs".format(ip))
            

    if(Linter):
        raise kopf.PermanentError('Lint failed')
    
    if(old != None and new == None):
        
        if(subnetReport['NumFreeNonStaticIPs'] == 0):
            logger.error("ERROR: There is no enough non-static IP to assign")
            raise kopf.TemporaryError('No enough IP')
        
        returnResult = returnIP(Network=namespacedNetowrk,clientName=name)

        if(type(returnResult) == dict and 'ErrorMsg' in returnResult):
        
            logger.error(returnResult['ErrorMsg'])
            raise kopf.PermanentError("can't release IP")
    
        if(returnResult != True):
            raise kopf.PermanentError("Can't release IP")

        requestedIP = requestIP(
        Network=namespacedNetowrk,
        clientName=name,
        IP=None
    )
    
        if(type(requestedIP) == dict):

            logger.error("ERROR : {0}".format(requestedIP['ErrorMsg']))
            
            if(requestedIP['ErrorCode'] == '805'):
                raise kopf.TemporaryError("Can't request IP for client")
            
            raise kopf.PermanentError("Can't request IP for client")

    if (new != None):

        if (isIPLeased(IP=new,Network=namespacedNetowrk)):

            logger.error("ERROR: the requested IP '{0}' is already leased".format(new))
            raise kopf.TemporaryError("Can't assign requested IP")
        
        returnResult = returnIP(Network=namespacedNetowrk,clientName=name)

        if(type(returnResult) == dict and 'ErrorMsg' in returnResult):
        
            logger.error(returnResult['ErrorMsg'])
            raise kopf.PermanentError("can't release IP")
    
        if(returnResult != True):
            raise kopf.PermanentError("Can't release IP")

        requestedIP = requestIP(
        Network=namespacedNetowrk,
        clientName=name,
        IP=new
    )
    
        if(type(requestedIP) == dict):

            logger.error("ERROR : {0}".format(requestedIP['ErrorMsg']))
            
            if(requestedIP['ErrorCode'] == '805'):
                raise kopf.TemporaryError("Can't request IP '{0}' for client".format(new))
            
            raise kopf.PermanentError("Can't request IP '{0}' for client".format(new))
    

    configMap_patch = {'data': {'IP': requestedIP }}

    try:
        core_v1_api.patch_namespaced_config_map(
            name="{0}.{1}".format(name,'tracerip'),
            namespace=namespace,
            body= configMap_patch
        )
    except ApiException as e:
        raise kopf.PermanentError("Can't access k8s API Server: %s\n" % e)

    logger.info("The client '{0}' IP is changed from '{1}' to '{2}'".format(name,currentIP,requestedIP))
