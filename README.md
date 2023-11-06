# github-monitoring

Lager metrikker av diverse tilstand i Github.

## GitHubs GraphQL-API

Vi bruker GraphQL-APIet til GitHub. Dette har et _skjema_ som beskriver alle operasjoner man kan gjøre. Oppdatert skjema
kan du laste ned her: [Public Schema](https://docs.github.com/en/graphql/overview/public-schema). GitHub kaller fila
`schema.docs.graphql`, men du kan kalle `schema.graphqls`. Maven-pluginen feiler om denne skjemafila slutter på `.graphql`.

For å teste ut spørringer, så har GitHub en fin interaktiv "explorer".
Den finner du her: [GraphQL API Explorer](https://docs.github.com/en/graphql/overview/explorer)
