import psycopg2

class Database:
    def __init__(self):
        self.conn = psycopg2.connect(
            database="linuxsandbox",
            user='linuxsandbox',
            password='c3ima@iitk',
            host='localhost',
            port= '5432'
        )

        self.cursor = self.conn.cursor()
    

    def check_status(self):
        self.cursor.execute("SELECT * FROM tasks;")
        data = self.cursor.fetchall()
        print(data)

    def sql_query_data(self, query):
        self.cursor.execute(query)
        data = self.cursor.fetchall()
        #self.conn.commit()

        return data

    def sql_query_commit(self, query):
        self.cursor.execute(query)
        self.conn.commit()


    def create_table(self):
        query = "CREATE TABLE tasks (\
                    id SERIAL PRIMARY KEY,\
                    filename VARCHAR(255) NOT NULL,\
                    vm_machine VARCHAR(50),\
                    status VARCHAR(50) NOT NULL,\
                    added_on TIMESTAMP,\
                    started_on TIMESTAMP,\
                    completed_on TIMESTAMP\
                );"
        self.cursor.execute(query)
        self.conn.commit()

    
    def __del__(self):
        self.conn.commit()
        self.conn.close()

#db = Database()
#db.create_table()
#db.sql_query_commit("INSERT INTO tasks VALUES (3, 'netstat', 'REMnux', 'started', Null, Null);")
#db.sql_query_commit("DELETE FROM tasks;")
#db.sql_query_commit("DROP TABLE IF EXISTS machines;")
#db.sql_query_commit("CREATE TABLE machines (id SERIAL PRIMARY KEY, machine VARCHAR(50),availability VARCHAR(50) NOT NULL);")
#print(db.sql_query_data("SELECT id FROM tasks where filename='/home/poonia/Documents/tools/final_code/test/31a13b6b7f6b63c34bdf7f68153dceffb93b022374940aeecea5238de1b16dcc.elf';")[0][0])
#db.check_status()
#pending_files = db.sql_query_data("SELECT vm_machine FROM tasks WHERE filename='dig';")[0][0]
#if(not pending_files):
#    print(pending_files)
#db.sql_query_data("SELECT machine FROM machines WHERE availability='available';")

