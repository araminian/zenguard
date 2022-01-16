import zenguard.utils.wireguard.model as wg_models
import configparser
from pathlib import Path , PurePath
from pydantic import ValidationError
import os
from netaddr import IPAddress

def clientGenerate(clients,server,subnet,outputDir):
    serverMask =IPAddress(subnet['mask']).netmask_bits()
    clientUnControll = []


    for client in clients:
        if (client['privateKey'] == ''):
            client['privateKey'] = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
            clientUnControll.append(client['name'])
                
        # TODO do we need listenport for client ? 
        clientInterface = wg_models.InterfaceModel (
        PrivateKey = wg_models.KeyModel(Key=client['privateKey']),
        CommentKey = "Interface" ,
        CommentValue = client['name'],
        Address = "{0}/{1}".format(client['IPAddress'],serverMask)
            )
        clientRoute = client['routes'].split(",")

        serverAsPeer = wg_models.PeerModel(
        PublicKey = wg_models.KeyModel(Key=server['publicKey']),
        AllowedIPs = clientRoute,
        Endpoint = wg_models.EndpointModel (
        Address = server['publicIPAddress'],
        Port = int(server['port'])
                ),
                CommentKey = "Peer" , 
                CommentValue = "Server"
            )
        serverPeer = []
        serverPeer.append(generate_peer(serverAsPeer))
        configComponentsClient = wg_models.ConfigComponentsModel(
        Interface = generate_interface(clientInterface),
            Peers = serverPeer,
            ConfigPath = '{1}/wg-{0}.conf'.format(client['name'],outputDir)
                )
        generate_wg_conf_file(configComponentsClient)
    return clientUnControll


def serverGenerate(clients,server,subnet,outputDir,networkName):
    # Generate Server Configuration
    serverAddress = server['IPAddress']
    serverMask =IPAddress(subnet['mask']).netmask_bits()
    ServerInterface =  wg_models.InterfaceModel (
    PrivateKey = wg_models.KeyModel(Key=server['privateKey']),
    ListenPort = int(server['port']),
    CommentKey = "Interface" ,
    CommentValue = networkName,
    Address = "{0}/{1}".format(serverAddress,serverMask)
            )

    clientAsPeer = []

    for client in clients:
        clientModel = wg_models.PeerModel(
            PublicKey = wg_models.KeyModel(Key=client['publicKey']),
            AllowedIPs = ["{0}/32".format(client['IPAddress'])],
            CommentKey = "Client" , 
            CommentValue = client['name']
                )
        clientAsPeer.append(generate_peer(clientModel))
            
    configComponents = wg_models.ConfigComponentsModel(
    Interface = generate_interface(ServerInterface),
    Peers = clientAsPeer,
    ConfigPath = '{0}/wg-server.conf'.format(outputDir)
        )
    generate_wg_conf_file(configComponents)

def generate_interface(interface: wg_models.InterfaceModel):

    interfaceDict = {}

    commentKey = "# {0} ".format(interface.CommentKey)
    interfaceDict [commentKey] = interface.CommentValue
    interfaceDict ['Address'] = interface.Address
    if (interface.ListenPort != None):
        interfaceDict ['ListenPort'] = interface.ListenPort
    interfaceDict ['PrivateKey'] = interface.PrivateKey.Key
    
    
    return interfaceDict

def generate_peer(peer: wg_models.PeerModel):

    peerDict = {}

    commentKey = "# {0} ".format(peer.CommentKey)
    peerDict [commentKey] = peer.CommentValue

    peerDict ['PublicKey'] = peer.PublicKey.Key
    if (peer.PreSharedKey != None):
        peerDict ['PreSharedKey'] = peer.PreSharedKey.Key

    peerDict ['AllowedIPs'] = ", ".join(peer.AllowedIPs)

    if (peer.Endpoint == None):
        return peerDict

    EndpointAddress = peer.Endpoint.Address
    EndpointHostname = peer.Endpoint.Hostname

    if EndpointAddress:

        peerDict ['Endpoint'] = "{0}:{1}".format(EndpointAddress,peer.Endpoint.Port)
    else:
        peerDict ['Endpoint'] = "{0}:{1}".format(EndpointHostname,peer.Endpoint.Port)
    return peerDict


def generate_wg_conf_file(configModel: wg_models.ConfigComponentsModel):

    Interface = configModel.Interface
    Peers = configModel.Peers
    ConfigPath = configModel.ConfigPath

    path = PurePath(ConfigPath)
    parentPath = path.parent
    if(not Path(parentPath).exists()):
        os.mkdir(parentPath)
    if(Path(ConfigPath).exists()):
        os.remove(path)

    interfaceConfig = configparser.ConfigParser(strict=False,defaults=None)
    interfaceConfig.optionxform = str

    interfaceConfig['Interface'] = Interface

    with open(ConfigPath, 'a') as interfaceConfigFile:
        interfaceConfig.write(interfaceConfigFile)

    for p in Peers:
        with open(ConfigPath , 'a') as peerConfigFile:
            configPeer = configparser.ConfigParser(strict=False,defaults=None)
            configPeer.optionxform = str
            configPeer['Peer'] = p
            configPeer.write(peerConfigFile)