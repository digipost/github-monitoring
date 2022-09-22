package no.digipost.github.monitoring

import com.apollographql.apollo3.ApolloClient
import com.apollographql.apollo3.api.Optional
import com.github.graphql.client.GetVulnerabilityAlertsForRepoQuery
import com.github.graphql.client.QueryRepositoriesQuery
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.internal.toImmutableList
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.time.ZonedDateTime

data class Repos(val all: List<Repository>, val onlyVulnerable: List<Repository>)

val logger: Logger = LoggerFactory.getLogger("no.digipost.github.monitoring.GithubGraphql")

fun fetchAllReposWithVulnerabilities(apolloClient: ApolloClient): Repos {
    val repositoryChannel = Channel<Repository>()
    val repositories = mutableListOf<Repository>()
    val vulnRepositories = mutableListOf<Repository>()

    runBlocking {
        launch {
            val listRepos = listRepos(apolloClient, repositoryChannel)
            repositoryChannel.close()
        }

        launch {
            for (r in repositoryChannel) {
                launch {// Kan være launch, men jeg har sett 502 fra apiet. Bombing kan kanskje skape problemer.
                    val vulnerabilities = getVulnerabilitiesForRepo(apolloClient, r.name)
                    r.copy(vulnerabilities = vulnerabilities).let {
                        repositories.add(it)
                        if (it.vulnerabilities.isNotEmpty()) {
                            logger.info("${vulnerabilities.size} sårbarheter i ${r.name}")
                            vulnRepositories.add(it)
                        }
                    }
                }
            }
        }
    }
    return Repos(repositories, vulnRepositories)
}


private suspend fun getVulnerabilitiesForRepo(
    apolloClient: ApolloClient,
    name: String
): List<Vulnerability?> {
    if(logger.isDebugEnabled) logger.debug("henter sårbarheter for repo $name")
    val response = apolloClient.query(GetVulnerabilityAlertsForRepoQuery(name, "digipost")).execute()

    val vulnerabilityAlerts = response.data?.repository?.vulnerabilityAlerts?.nodes ?: emptyList()
    val vulnerabilities = vulnerabilityAlerts.map {
        it?.let {
            Vulnerability(
                it.securityVulnerability!!.severity.name,
                ZonedDateTime.now(),
                it.securityVulnerability.`package`.name,
                it.securityVulnerability.advisory.description,
                it.securityVulnerability.advisory.cvss.score,
                it.securityVulnerability.advisory.identifiers.firstOrNull { identifier -> "CVE" == identifier.type }?.value
                    ?: "ukjent CVE"
            )
        }
    }.toImmutableList()

    return vulnerabilities
}


private suspend fun listRepos(apolloClient: ApolloClient, repositoryChannel: Channel<Repository>): List<Repository> {
    val mutableListOf = mutableListOf<Repository>()

    if(logger.isDebugEnabled) logger.debug("Henter repoer med owner 'digipost' som ikke er arkiverte og har språk i listen $LANGUAGES")

    var cursor: String? = null
    var hasNext = true

    while (hasNext) {
        if(logger.isDebugEnabled) logger.debug("henter repoer fra Github ${if (cursor != null) " etter: $cursor" else " fra toppen"}")

        val response = apolloClient.query(QueryRepositoriesQuery(Optional.Present(cursor))).execute()

        response.data?.viewer?.repositories?.nodes
            ?.filter { "digipost" == it?.owner?.login && !it.isArchived }
            ?.filter { LANGUAGES.contains(it?.languages?.nodes?.firstOrNull()?.name) }
            ?.forEach {
                it?.let {
                    repositoryChannel.send(
                        Repository(
                            it.owner.login,
                            it.name,
                            it.languages?.nodes!![0]?.name ?: "unknown"
                        )
                    )
                }
            }

        hasNext = response.data?.viewer?.repositories?.pageInfo?.hasNextPage ?: false

        cursor = response.data?.viewer?.repositories?.pageInfo?.endCursor
    }


    return mutableListOf
}
