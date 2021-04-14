#!/usr/bin/python

from mysql.connector import MySQLConnection, Error
from mysql_dbconfig import read_db_config


def sql_insert(session_id, domain, http_code, count, raw_log):
    query = "INSERT INTO sla_code(session_id, domain, http_code, count, raw_log) " \
            "VALUES(%s,%s,%s, %s, %s)"
    try:
        db_config = read_db_config()
        conn = None
        conn = MySQLConnection(**db_config)

        cursor = conn.cursor()
        args = (str(session_id), str(domain), http_code, count, str(raw_log))
        cursor.execute(query, args)
        #        if cursor.lastrowid:
        #            print('last insert id', cursor.lastrowid)
        #            logging.info('last insert id' + str(cursor.lastrowid))
        #        else:
        #            print('last insert id not found')
        #            logging.error('Error: ' + str(domain) + str(e))
        conn.commit()
    except Error as error:
        print(error)
    finally:
        cursor.close()
        conn.close()