import ipaddress
from netaddr import IPNetwork
import netaddr
from typing import Union,Optional,List
from zenguard.utils.nacl.security import get_sha2
from zenguard.utils.database.table.add import add_entry_one,add_entry_multiple
from zenguard.utils.database.table.query import query_abstract
from zenguard.utils.database.table.delete import delete_abstract_one
from zenguard.utils.database.table.update import update_one_abstract
import datetime
from zenguard.utils.report.network import isNetworkInitialized
from zenguard.utils.database.core.db import delete_db

def isIPSmallerThan(smallIP: str , bigIP: str)-> bool:

    start = ipaddress.IPv4Address(smallIP)
    end = ipaddress.IPv4Address(bigIP)
    return start < end


def isValidCIDR(CIDR:str)->Union[bool,dict]:
    try:
        ipaddress.ip_network(CIDR)
        return True
    except ValueError:
        return {'ErrorCode':'806','ErrorMsg':"The {0} is not Valid CIDR".format(CIDR)}

def isValidIP(IP:str)->Union[bool,dict]:
    try:
        ipaddress.ip_address(IP)
        return True
    except ValueError:
        return {'ErrorCode':'806','ErrorMsg':"The {0} is not Valid IP Address".format(IP)}

def isIPinRange(range:Union[list,tuple],IP: str)->bool:
    return netaddr.IPAddress(IP) in netaddr.IPRange(range[0],range[1])

def isIPinCIDR(CIDR:str,IP:str)->bool:

    return netaddr.IPAddress(IP) in netaddr.IPNetwork(CIDR)

def getCIDRInfo(cidr:str)->dict:

    IPBlock = IPNetwork(cidr)
    IPInfo = {}
    IPInfo['cidr'] = str(IPBlock.cidr)
    IPInfo['firstIP'] = str(IPBlock[1])
    IPInfo['lastIP'] = str(IPBlock[-2])
    IPInfo['mask'] = str(IPBlock.netmask)
    IPInfo['size'] = str(IPBlock.size - 2) # Remove Network and Broadcast IP
    return IPInfo

def isLargerCIDR(new_CIDR:str,old_CIDR:str)->Union[bool,dict]:
    """
    Check the NEW CIDR is larger or supernet of OLD CIDR
    """
    
    # old_CIDR should be subnet of new_CIDR 
    newCidr = ipaddress.ip_network(new_CIDR)
    oldCidr = ipaddress.ip_network(old_CIDR)

    return oldCidr.subnet_of(newCidr)

def isOverlapCIDR(cidrA:str,cidrB:str)-> bool:
    """
    Check if the CIDR A have overlap with CIDR B
    """
    return ipaddress.IPv4Network(cidrA).overlaps(ipaddress.IPv4Network(cidrB))

def returnIP(Network:str,clientName:str)->Union[dict,bool]:

    clientID = get_sha2(clientName)
    findClientQuery = {"_id": clientID}
    queryResultObject= query_abstract(database_name=Network,table_name='leasedIP',query=findClientQuery)
    if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
        return queryResultObject
    queryResult =list(queryResultObject['Enteries'])

    if (len(queryResult) == 0):
        return {"ErrorCode":"802","ErrorMsg":"{0} has no leased IP address which can be released".format(clientName)}
    
    IP = queryResult[0]['IP']
    dataIP = {"_id": get_sha2(IP),"IP":IP,"static":queryResult[0]['static']}
    addResult = add_entry_one(database_name=Network,table_name='freeIP',data=dataIP)
    deleteResult = delete_abstract_one(database_name=Network,table_name='leasedIP',query=findClientQuery)
    
    if(type(addResult) == dict and 'ErrorMsg' in addResult):
        return addResult
    if (type(deleteResult) == dict and 'ErrorMsg' in deleteResult):
        return deleteResult
    return True

def requestIP(Network:str,clientName:str,IP:Optional[str]=None)->Union[dict,str]:

    # Check if the client has leased IPs
    clientID = get_sha2(clientName)
    findClientQuery = {"_id": clientID}
    queryResultObject= query_abstract(database_name=Network,table_name='leasedIP',query=findClientQuery)
    if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
        return queryResultObject
    
    queryResult =list(queryResultObject['Enteries'])
    
    if(len(queryResult) > 0):
        return {"ErrorCode":"801","ErrorMsg":"{0} has an IP address of {1}. It's not possible to get another IP.".format(clientName,queryResult[0]['IP'])}

    if(IP==None):

        findIPQuery = {"static":False}
        queryResultObject= query_abstract(database_name=Network,table_name='freeIP',query=findIPQuery)
        if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
            return queryResultObject
        queryResult =list(queryResultObject['Enteries'])
        if(len(queryResult) == 0):
            return {"ErrorCode":"805","ErrorMsg":"No IP available to assign"}
        
        ip2assign = queryResult[0]['IP']
        leaseDate = datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
        leaseInfo = {"_id":get_sha2(clientName),"Client": clientName,"IP":str(ip2assign),"LeaseDate":leaseDate,"static":False}

        addResult = add_entry_one(database_name=Network,table_name='leasedIP',data=leaseInfo)
        deleteResult = delete_abstract_one(database_name=Network,table_name='freeIP',query=queryResult[0])
        if ('ErrorMsg' in addResult or 'ErrorMsg' in deleteResult):
            return addResult
        return ip2assign

    else:
        # Check if the IP is free
        findIPQuery = {"IP": IP}
        queryResultObject= query_abstract(database_name=Network,table_name='leasedIP',query=findIPQuery)
        if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
            return queryResultObject
        queryResult =list(queryResultObject['Enteries'])
        if(len(queryResult) > 0):
            return {"ErrorCode":"804","ErrorMsg":"{0} is reserved for client {1} and can't be assigned to client {2}".format(IP,queryResult[0]['Client'],clientName)}

        # Find DesireIP and remove it from freeIP
        findIPQuery = {"IP": IP,"static":True}
        queryResultObject= query_abstract(database_name=Network,table_name='freeIP',query=findIPQuery)
        if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
            return queryResultObject
        queryResult =list(queryResultObject['Enteries'])
        if(len(queryResult) == 0):
            return {"ErrorCode":"805","ErrorMsg":"{0} is not availble to assign".format(IP)}

        leaseDate = datetime.datetime.now().strftime("%d-%m-%Y-%H-%M-%S")
        leaseInfo = {"_id":get_sha2(clientName),"Client": clientName,"IP":str(IP),"LeaseDate":leaseDate,"static":True}

        addResult = add_entry_one(database_name=Network,table_name='leasedIP',data=leaseInfo)
        deleteResult = delete_abstract_one(database_name=Network,table_name='freeIP',query=findIPQuery)
        if ('ErrorMsg' in addResult or 'ErrorMsg' in deleteResult):
            return addResult
        return IP


def initializeSubnet(Network:str ,CIDR:str,ReservedRange:Optional[str],ReservedIPs:Optional[List[str]])->bool:

    CIDRInfo = getCIDRInfo(CIDR)
    CIDRInfo['_id'] = get_sha2(Network)

    CIDRInfo['reservedRange'] = ReservedRange

    if (ReservedRange != None):
        CIDRInfo['reservedRange'] = ReservedRange
        reservedRangeParts = ReservedRange.split('-')
        reservedRangeIPParts = netaddr.IPRange(reservedRangeParts[0],reservedRangeParts[1])

    if (ReservedIPs != None):
        CIDRInfo['reservedIPs'] = ','.join(ReservedIPs)


    freeIPLIST = []
    IPBlock = IPNetwork(CIDR)
    for ip in IPBlock:
        
        if(ip == IPBlock.network or ip == IPBlock.broadcast):
            continue
            
        data = {}
        data['_id'] = get_sha2(str(ip))
        data['IP'] = str(ip)
        if (ReservedRange != None and ip in reservedRangeIPParts):
            data['static'] = True
        elif( ReservedIPs != None and str(ip) in ReservedIPs ):
            data['static'] = True
        else:
            data['static'] = False

        freeIPLIST.append(data)
    
    # Initilize
    initResult  = add_entry_one(database_name='Networks',table_name='init',data={'_id':get_sha2(Network),'network':Network,'initilized':True, 'cidr':CIDR})

    if (type(initResult) == dict and 'ErrorMsg' in initResult):
        return initResult
    
    # Subnet Information
    subnetResult = add_entry_one(database_name=Network,table_name='subnet',data=CIDRInfo)

    if(type(subnetResult) == dict and 'ErrorMsg' in subnetResult):
        return subnetResult
    
    # Free IP Information
    freeIPResult = add_entry_multiple(database_name=Network,table_name='freeIP',data=freeIPLIST)

    if (type(freeIPResult) == dict and 'ErrorMsg' in freeIPResult):
        return freeIPResult
    
    return True

def subtractCIDR(LargeSubnet:str,SmallSubnet:str)->list:

    largeCidr = ipaddress.ip_network(LargeSubnet)
    smallCidr = ipaddress.ip_network(SmallSubnet)

    return sorted(list(set(largeCidr) - set(smallCidr)))

def makeSubnetLarger(Network:str,NewCIDR:str,OldCIDR:str)-> Union[dict,bool]:


    isInitialized = isNetworkInitialized(Network=Network)

    if (type(isInitialized) == dict):
        return isInitialized
    if (type(isInitialized) == tuple and not isInitialized[0]):
        return {"ErrorCode":"300","ErrorMsg":"ERROR: The network {0} is not initialized".format(Network)}

    if not isLargerCIDR(new_CIDR=NewCIDR,old_CIDR=OldCIDR):
        return {"ErrorCode":"301","ErrorMsg":"ERROR: The new subnet '{0}' is not supernet of old subnet '{1}'.".format(NewCIDR,OldCIDR)}

    additionalIPs = subtractCIDR(NewCIDR,OldCIDR)
    
    newCIDRInfo = getCIDRInfo(NewCIDR)
    newCIDRInfo['_id'] = get_sha2(Network)
     
    # Update init table
    networkQuery = {"_id":get_sha2(Network)}
    newInitValue = { "$set": { "cidr": NewCIDR } }
    resultUpadte = update_one_abstract(database_name='Networks',table_name='init',query=networkQuery,newvalue=newInitValue)
    if (type(resultUpadte) == dict and 'ErrorCode' in resultUpadte):
        return resultUpadte
    

    # Update subnet table

    subnetQuery = {"_id":get_sha2(Network)}
    newSubnetValues = {"$set":{"cidr":NewCIDR,"firstIP":newCIDRInfo['firstIP'],"lastIP":newCIDRInfo['lastIP'],'mask':newCIDRInfo['mask'],'size':newCIDRInfo['size']}}
    resultUpadte = update_one_abstract(database_name=Network,table_name='subnet',query=subnetQuery,newvalue=newSubnetValues)
    if (type(resultUpadte) == dict and 'ErrorCode' in resultUpadte):
        return resultUpadte
    
    # Update FreeIP Table
    lastIPofOldSubnet = ipaddress.IPv4Network(OldCIDR)[-1]
    additionalIPs.append(ipaddress.IPv4Address(lastIPofOldSubnet))
    additionalIPs= sorted(additionalIPs)
    del additionalIPs[-1] # remove broadcast IP

    freeIPLIST = []
    for ip in additionalIPs:
        data = {}
        data['_id'] = get_sha2(str(ip))
        data['IP'] = str(ip)
        data['static'] = False

        freeIPLIST.append(data)
        
    resultAddIPs = add_entry_multiple(database_name=Network,table_name='freeIP',data=freeIPLIST)
    if (type(resultAddIPs) == dict and 'ErrorCode' in resultAddIPs):
        return resultAddIPs
    
    return True

def removeNetwork(
    Network: str
):
    isInitialized = isNetworkInitialized(Network=Network)

    if (type(isInitialized) == dict):
        return isInitialized
    if (type(isInitialized) == tuple and not isInitialized[0]):
        return {"ErrorCode":"300","ErrorMsg":"ERROR: The network {0} is not initialized".format(Network)}

    delete_db(Network)
    networkQuery = {"_id":get_sha2(Network)}
    result = delete_abstract_one(database_name='Networks',table_name='init',query=networkQuery)
    if(type(result) == dict and 'ErrorCode' in result ):
        return result
    return True

def isIPLeased(IP:str,Network:str) -> bool:

    findIPQuery = {"IP": IP}
    queryResultObject= query_abstract(database_name=Network,table_name='leasedIP',query=findIPQuery)
    if (type(queryResultObject) == dict and 'ErrorCode' in queryResultObject):
        return queryResultObject
    queryResult =list(queryResultObject['Enteries'])
    if(len(queryResult) > 0):
        return True
    
    return False
