import pymongo

from config import mongo_client, db_name, collection_name


def connect_mongodb():
    myclient = pymongo.MongoClient(mongo_client)
    dblist = myclient.list_database_names()
    if db_name in dblist:
        mydb = myclient[db_name]
        col = mydb.users
        return mydb
    else:
        return False