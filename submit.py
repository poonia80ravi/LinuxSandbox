from db import Database
import argparse
import datetime

def main():

    db = Database()
    parser = argparse.ArgumentParser()
    parser.add_argument('--filename',help='Filename', type=str, required=True, nargs='+')
    parser.add_argument('--machine', help='Virtual machine name where you want to analyze.',type=str)
    parser.add_argument('--timeout', help='For how many seconds you want run the malicious file', type=int, default=60)
    args = parser.parse_args()

    if(args.machine):
        for i in args.filename:
            filename = i
            id = db.sql_query_data("SELECT COUNT(*) FROM tasks;")[0][0]
            machine = args.machine
            started_on = datetime.datetime.now().timestamp()
            query = "INSERT INTO tasks VALUES ("+str(id)+", '"+filename+"', '"+str(machine)+"', 'pending',TO_TIMESTAMP("+str(started_on)+"), Null, Null);"
            db.sql_query_commit(query)
            db.check_status()
    else:
        for i in args.filename:
            filename = i
            id = db.sql_query_data("SELECT COUNT(*) FROM tasks;")[0][0]
            added_on = datetime.datetime.now().timestamp()
            query = "INSERT INTO tasks VALUES ("+str(id)+", '"+filename+"', Null, 'pending', TO_TIMESTAMP("+str(added_on)+"), Null, Null);"
            db.sql_query_commit(query)
            db.check_status()

    pending_files = db.sql_query_data("SELECT filename FROM tasks WHERE status='pending';")
        
        




if __name__ == "__main__":
    main()
