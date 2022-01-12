from zenguard.utils.database.core import collection

def update_one_abstract (database_name,table_name,query,newvalue):

    table = collection.get_collection(database_name,table_name)
    if(type(table) == dict and 'ErrorCode' in table):
        return table
    try:
        entries = table.update_one(query, newvalue)
    except Exception as e:
        return {"ErrorCode":"700","ErrorMsg":e}
    else:
        return {"StatusCode":"200","Enteries":entries}