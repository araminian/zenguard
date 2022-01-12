from zenguard.utils.database.core.db import get_db

def get_collection(db_name,collection_name):
    
    DB = get_db(db_name)
    if (type(DB) == dict and 'ErrorCode' in DB):
        return DB
    collectionsList = DB.list_collection_names()
    if collection_name in collectionsList:
        return DB[collection_name]
    else:
        return DB[collection_name]