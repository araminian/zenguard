from zenguard.utils.database.core import collection

def query_abstract(database_name,table_name,query):

    table = collection.get_collection(database_name,table_name)
    if(type(table) == dict and 'ErrorCode' in table):
        return table
    try:
        entries = table.find(query)
    except Exception as e:
        return {"ErrorCode":"700","ErrorMsg":e}
    else:
        return {"StatusCode":"200","Enteries":entries}