import os

from pymongo import MongoClient

mongo_client = MongoClient(os.getenv("DB"))
database = mongo_client[os.getenv("MONGO_DB_NAME", "Cluster0")]