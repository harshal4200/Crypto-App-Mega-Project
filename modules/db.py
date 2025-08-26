from config import Config
import pymysql

def get_connection():
    print("🔍 DB_USER:", Config.DB_USER)
    print("🔍 DB_PASSWORD:", Config.DB_PASSWORD)  # <-- check yaha
    return pymysql.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )
