Fixtures for the GitHub connector. Shapes follow the examples in the vendor
docs (https://docs.github.com/en/rest); they were **not fetched**, because the
tests have no internet. The array responses (`issues_list.json`,
`pulls_list.json`) cannot hold a `_source` key, so this file is their source
note: https://docs.github.com/en/rest/issues/issues#list-repository-issues and
https://docs.github.com/en/rest/pulls/pulls#list-pull-requests.

`link_header.txt` follows the pagination page,
https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api.
