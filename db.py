import psycopg2


def get_db():
    conn = psycopg2.connect(dbname='postgres', user='admin',
                                password='excellent',
                                host='db')

    cur = conn.cursor()
    cur.execute('''DROP TABLE IF EXISTS Item;
                    CREATE TABLE Item (
                      id INTEGER UNIQUE PRIMARY KEY,
                      name TEXT,
                      category TEXT
                    );
                    INSERT INTO Item VALUES (1, 'cookies', 'food');
                    INSERT INTO Item VALUES (2, 'phone', 'electronics');
                    INSERT INTO Item VALUES (3, 'headphones', 'electronics');
                    INSERT INTO Item VALUES (4, 'bread', 'food');''')
    cur.close()
    return conn
