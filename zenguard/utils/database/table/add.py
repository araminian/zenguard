from zenguard.utils.database.core import collection
import pymongo

def add_entry_one (database_name,table_name,data):

    table = collection.get_collection(database_name,table_name)
    if(type(table) == dict and 'ErrorCode' in table):
        return table

    if(type(data) != dict):
        return {"ErrorCode":"700","ErrorMsg":"The Data that you want to insert is not in good format!"}
    try:
      dataID = table.insert_one(data)
    except pymongo.errors.DuplicateKeyError:
        return {"ErrorCode":"701","ErrorMsg":"Duplicate Key Error"} 
    except Exception as e:
        return {"ErrorCode":"700","ErrorMsg":e}
    else:    
        return {"StatusCode":"200","DataID":dataID}


def add_entry_multiple (database_name,table_name,data):

    table = collection.get_collection(database_name,table_name)
    if(type(table) == dict and 'ErrorCode' in table):
        return table_name

    if(type(data) != list):
        return {"ErrorCode":"700","ErrorMsg":"The Data that you want to insert is not in good format!"}
    
    try:    
      dataIDs = table.insert_many(data)
    except Exception as e:
      return {"ErrorCode":"700","ErrorMsg":e}
    else:
      return {"StatusCode":"200","DataID":dataIDs}