import pymongo
from zenguard.utils.general.parse import parseYAML
from zenguard.utils.general.osFunc import readEnvVar
import os
import urllib

def getMongoConnectionInformation() -> dict:

    dirname = os.path.dirname(__file__)
    settingsFilePath = os.path.join(dirname, '../../../settings.yaml')
    
    parsedYAML = parseYAML(settingsFilePath)

    if (type(parsedYAML) and 'ErrorMsg' in parsedYAML):
        return parsedYAML
    
    mongoDBSettings = parsedYAML['MongoDB']['Connection']
    
    connectionInformation = {}
    for info,envVar in mongoDBSettings.items():
        envValue = readEnvVar(EnvVar=envVar)
        if (type(envValue) == dict and 'ErrorMsg' in envValue):
          return envValue
        connectionInformation[info] = envValue
    return connectionInformation

def getMongoClient():

    connectionInformation = getMongoConnectionInformation()
    
    if (type(connectionInformation) == dict and 'ErrorMsg' in connectionInformation):
        return {"ErrorCode":"700","ErrorMsg":"Can't connect to the Database. Reason: {0}".format(connectionInformation['ErrorMsg'])}
    
    username = urllib.parse.quote_plus(connectionInformation['User'])
    password = urllib.parse.quote_plus(connectionInformation['Password'])

    serverAddress = connectionInformation['Addresss']
    
    accessURL = "mongodb://{0}:{1}@{2}".format(username,password,serverAddress)
    client = pymongo.MongoClient(accessURL)
    # https://pymongo.readthedocs.io/en/stable/migrate-to-pymongo3.html#mongoclient-connects-asynchronously
    try:
        DBs = client.list_database_names()
    except pymongo.errors.ConnectionFailure as e:
        Error = {"ErrorCode":"700","ErrorMsg":e}
        return Error
    except pymongo.errors.ServerSelectionTimeoutError as e:
        Error = {"ErrorCode":"700","ErrorMsg":e}
        return Error
    except pymongo.errors.OperationFailure as e:
        Error = {"ErrorCode":"700","ErrorMsg":e}
        return Error
    except :
        Error = {"ErrorCode":"700","ErrorMsg":"Other Errors"}
    else:
        return client