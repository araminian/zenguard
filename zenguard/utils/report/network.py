import typing
from zenguard.utils.database.table.query import query_abstract
from zenguard.utils.database.table.get import get_all_entries
from typing import Union,Tuple
from zenguard.utils.nacl.security import get_sha2


def isNetworkInitialized(Network:str)->Union[dict,Tuple[bool,list]]:

    query = {"_id":get_sha2(Network)}

    queryResult = query_abstract(database_name='Networks',table_name='init',query=query)

    if (type(queryResult) == dict and 'ErrorMsg' in queryResult):

        return queryResult
    
    networkInit = list(queryResult['Enteries'])

    if (len(networkInit) == 0 ):
        return (False,None)

    return (True,networkInit)

def getInitializedNetwork()->Union[dict,list]:

    network = get_all_entries(database_name='Networks',table_name='init')
    if (type(network) == dict and 'ErrorCode' in network):
        return network
    networkInit = list(network['Enteries'])

    return networkInit

def getNetworkReport(Network):

    subnetReport = {}

    findNonStaticQuery = {"static":False}
    findStaticQuery = {"static":True}

    queryFreeNonStatic= query_abstract(database_name=Network,table_name='freeIP',query=findNonStaticQuery)
    if (type(queryFreeNonStatic) == dict and 'ErrorCode' in queryFreeNonStatic):
        return queryFreeNonStatic
    
    freeNonStatic= list(queryFreeNonStatic['Enteries'])


    queryFreeStatic = query_abstract(database_name=Network,table_name='freeIP',query=findStaticQuery)
    if (type(queryFreeStatic) == dict and 'ErrorCode' in queryFreeStatic):
        return queryFreeStatic

    freeStatic = list(queryFreeStatic['Enteries'])
    

    queryLeasedNonStatic = query_abstract(database_name=Network,table_name='leasedIP',query=findNonStaticQuery)
    if (type(queryLeasedNonStatic) == dict and 'ErrorCode' in queryLeasedNonStatic):
        return queryLeasedNonStatic
    
    leasedNonStatic = list(queryLeasedNonStatic['Enteries'])

    queryLeasedStatic = query_abstract(database_name=Network,table_name='leasedIP',query=findStaticQuery)
    if (type(queryLeasedStatic) == dict and 'ErrorCode' in queryLeasedStatic):
        return queryLeasedStatic
    
    leasedStatic = list(queryLeasedStatic['Enteries'])

    subnetReport = {
        'NumFreeNonStaticIPs': len(freeNonStatic),
        'FreeNonStaticIPs': freeNonStatic,
        'NumFreeStaticIPs': len(freeStatic),
        'FreeStaticIPs': freeStatic,
        'NumLeasedNonStaticIPs': len(leasedNonStatic),
        'LeasedNonStaticIPs': leasedNonStatic,
        'NumLeasedStaticIPs': len(leasedStatic),
        'LeasedStaticIPs': leasedStatic
    }

    return subnetReport

def getSubnetInfo(Network:str)->dict:

    isNetworkReady = isNetworkInitialized(Network=Network)

def getClientIP(Network:str,Client:str)-> Union[bool,str]:

    clientID = get_sha2(Client)
    findClientQuery = {"_id": clientID}
    queryResultObject= query_abstract(database_name=Network,table_name='leasedIP',query=findClientQuery)
    if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
        return queryResultObject
    
    queryResult =list(queryResultObject['Enteries'])
    
    if(len(queryResult) > 0):
        return queryResult[0]['IP']
    return False

def getClients(networkName):

    isInitialized = isNetworkInitialized(networkName)
    if(type(isInitialized) == dict):
        return isInitialized
    
    clients = get_all_entries(database_name=networkName,table_name='clients')
    if (type(clients) == dict and 'ErrorCode' in clients):
        return clients

    clientList = list(clients['Enteries'])

    return clientList

def getSubnet(networkName):
    
    isInitialized = isNetworkInitialized(networkName)
    if(type(isInitialized) == dict):
        return isInitialized
    
    subnet = get_all_entries(database_name=networkName,table_name='subnet')
    if (type(subnet) == dict and 'ErrorCode' in subnet):
        return subnet

    subnetObject = list(subnet['Enteries'])[0]
    return subnetObject