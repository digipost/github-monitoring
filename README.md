# github-monitoring

Lager metrikker av diverse tilstand i Github.

## GitHubs GraphQL-API

Vi bruker GraphQL-APIet til GitHub. Dette har et _skjema_ som beskriver alle operasjoner man kan gjøre. Oppdatert skjema
kan du laste ned her: [Public Schema](https://docs.github.com/en/graphql/overview/public-schema). GitHub kaller fila
`schema.docs.graphql`, men du kan kalle `schema.graphqls`. Maven-pluginen feiler om denne skjemafila slutter på `.graphql`.

For å teste ut spørringer, så har GitHub en fin interaktiv "explorer".
Den finner du her: [GraphQL API Explorer](https://docs.github.com/en/graphql/overview/explorer)

----

## Slackintegrasjon

Denne applikasjonen kan settes opp med en slackbotintegrasjon. Da må man i så fall gi en slack webhook url som input.

- For å aktivere slackvarslinger settes miljøvariabelen `SLACK_WEBHOOK_URL` til en webhook url som du har fått fra slackboten du har laget
- For å velge hvilket nivå av sårbarheter som skal varsles (UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL) kan man sette en miljøvariabel `severity_limit`. Da vil boten kun varsle om sårbarheter med lik eller høyere alvorlighet.
