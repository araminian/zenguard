from zenguard.utils.database.core.connection import getMongoClient

def get_db(dbName):
    
    mongoClient = getMongoClient()
    if(type(mongoClient) == dict and 'ErrorCode' in mongoClient):
        return mongoClient
    dblist = mongoClient.list_database_names()
    return mongoClient[dbName]

def delete_db(dbName):
    mongoClient = getMongoClient()
    mongoClient.drop_database(dbName)