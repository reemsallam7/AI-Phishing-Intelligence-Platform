import os

from pymongo import MongoClient

mongo_uri = os.getenv("MONGO_URI") or os.getenv("DB")
database_name = os.getenv("MONGO_DB_NAME", "Cluster0")

mongo_client = MongoClient(
    mongo_uri,
    serverSelectionTimeoutMS=int(os.getenv("MONGO_TIMEOUT_MS", "5000")),
)
database = mongo_client[database_name]
