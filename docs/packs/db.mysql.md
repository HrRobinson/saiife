# DB: mysql (db.mysql)

This pack stops MySQL statements that destroy data or hand out full rights:
deleting a database or table, emptying a table, deleting every row, and
granting all privileges. It looks at statements on a command line that runs
the MySQL tools (`mysql -e "..."`, `mysqladmin`).

## On by default

No. Turn it on for a project in your own terminal:

- run `saiife init --pack db.mysql`, or
- add the id to the `packs` list in `.saiife/config.toml`, for example
  `packs = ["db.mysql"]`.

To turn it off, remove the id from that list. An agent cannot change this
file (the `core.self` pack blocks it).

## Blocked

- `DROP DATABASE` and `DROP SCHEMA`. They destroy a whole database.
- `DROP TABLE`. It destroys a table and all its data.
- `TRUNCATE`. It empties a table, and the rows cannot be rolled back one by
  one.
- `DELETE` without a `WHERE` clause. It removes every row in the table.
- `GRANT ALL`. It gives full rights on the target.
- `mysqladmin drop`. It destroys a whole database.

Upper and lower case are treated the same.

## Allowed on purpose

- Reading: `SELECT`, `SHOW`.
- `DELETE` with a `WHERE` clause.
- Backups and status checks: `mysqldump`, `mysqladmin status`,
  `mysqladmin ping`.
- Opening the MySQL shell (`mysql prod`).

## Not covered

- Statements typed inside an interactive `mysql` shell are not seen.
- Statements in a file fed to `mysql` (`mysql db < file.sql`) are not seen;
  only the command line is judged.
- A raw SQL statement without the `mysql` program on the line is out of scope
  for this pack (the `db.postgres` pack judges raw SQL).
- `UPDATE` without a `WHERE` clause and `ALTER TABLE ... DROP COLUMN` are
  allowed.

## Examples

```saiife-examples
deny mysql -e "DROP DATABASE prod"
deny mysql -e "drop table users"
deny mysql -e "TRUNCATE TABLE sessions"
deny mysql -e "DELETE FROM users"
deny mysql -e "GRANT ALL ON *.* TO 'bob'@'%'"
deny mysqladmin drop proddb
allow mysql -e "SELECT * FROM users"
allow mysql -e "DELETE FROM users WHERE id = 1"
allow mysqldump prod > backup.sql
allow mysqladmin status
```
