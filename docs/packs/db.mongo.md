# DB: mongo (db.mongo)

This pack stops MongoDB shell commands that wipe data: deleting a whole
database, deleting a collection, and deleting every document in a
collection. It looks at commands given to the MongoDB shell (`mongosh` or
`mongo`), most often with `--eval`.

## On by default

No. Turn it on for a project in your own terminal:

- run `saiife init --pack db.mongo`, or
- add the id to the `packs` list in `.saiife/config.toml`, for example
  `packs = ["db.mongo"]`.

To turn it off, remove the id from that list. An agent cannot change this
file (the `core.self` pack blocks it).

## Blocked

- `db.dropDatabase()`. It destroys the whole database.
- `db.<collection>.drop()`. It destroys the collection and all its documents.
- `db.<collection>.deleteMany({})` with an empty filter. It deletes every
  document in the collection.
- `db.<collection>.remove({})` with an empty filter. Same effect.

## Allowed on purpose

- Reading: `find`, `findOne`, `aggregate`, `countDocuments`.
- Deleting with a filter: `deleteOne`, and `deleteMany` or `remove` with a
  non-empty filter such as `{status: 'old'}`.
- Index maintenance: `dropIndex` and `dropIndexes`. They touch no documents.
- A collection that is only named like an operation, for example `drop_me`.

## Not covered

- Only commands with the `mongosh` or `mongo` program name on the line are
  judged. A script file run by the shell (`mongosh script.js`) and commands
  typed inside an interactive shell are not seen.
- A filter that matches everything but is not empty (`deleteMany({_id: {$exists: true}})`)
  is allowed.
- `updateMany` that overwrites every document is allowed.

## Examples

```saiife-examples
deny mongosh --eval "db.dropDatabase()"
deny mongosh mydb --eval "db.users.drop()"
deny mongosh --eval "db.logs.deleteMany({})"
deny mongo --eval "db.logs.remove({})"
allow mongosh --eval "db.users.find({})"
allow mongosh --eval "db.logs.deleteMany({status: 'old'})"
allow mongosh --eval "db.users.dropIndex('email_1')"
allow mongosh --version
```
