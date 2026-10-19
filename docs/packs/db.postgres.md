# DB: postgres (db.postgres)

This pack stops PostgreSQL statements that destroy data: deleting a
database, schema or table, emptying a table, and deleting every row. It
looks at raw SQL on the command line, at `psql -c "..."` and at the
`dropdb` tool.

## On by default

No. Turn it on for a project in your own terminal:

- run `saiife init --pack db.postgres`, or
- add the id to the `packs` list in `.saiife/config.toml`, for example
  `packs = ["db.postgres"]`.

To turn it off, remove the id from that list. An agent cannot change this
file (the `core.self` pack blocks it).

## Blocked

- `DROP DATABASE`. It destroys a whole database.
- `DROP SCHEMA`. It destroys a schema and everything in it.
- `DROP TABLE`. It destroys a table and all its data.
- `TRUNCATE`. It empties a table, and the rows cannot be rolled back one by
  one.
- `DELETE` without a `WHERE` clause. It removes every row in the table.
- `dropdb`. It destroys a whole database.

Upper and lower case are treated the same.

## Allowed on purpose

- Reading: `SELECT`.
- `DELETE` with a `WHERE` clause.
- Opening `psql`, creating a database (`createdb`) and backups (`pg_dump`).

## Not covered

- Statements typed inside an interactive `psql` shell are not seen.
- Statements in a file (`psql -f file.sql`, `psql < file.sql`) are not seen;
  only the command line is judged.
- `UPDATE` without a `WHERE` clause and `ALTER TABLE ... DROP COLUMN` are
  allowed.

It also blocks too much in one case. This is the safe direction: the pack
looks for the words anywhere on the line, so a command that only mentions
them is blocked too, for example `git commit -m "drop table users"`.

## Examples

```saiife-examples
deny psql -c "DROP TABLE users"
deny psql mydb -c "drop database prod"
deny psql -c "TRUNCATE users"
deny psql -c "DELETE FROM sessions"
deny dropdb proddb
deny git commit -m "drop table users"
allow psql -c "SELECT * FROM users"
allow psql -c "DELETE FROM sessions WHERE id = 1"
allow pg_dump mydb > backup.sql
allow createdb newdb
```
