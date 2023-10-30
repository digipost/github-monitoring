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
import java.io.IOException
import java.time.ZonedDateTime

data class Repos(val all: List<Repository>)

val logger: Logger = LoggerFactory.getLogger("no.digipost.github.monitoring.GithubGraphql")

const val daysToCount = 30

fun fetchAllReposWithVulnerabilities(apolloClient: ApolloClient, githubApiClient: GithubApiClient): Repos {
    val repositoryChannel = Channel<Repository>()
    val repositories = mutableListOf<Repository>()
    val vulnRepositories = mutableMapOf<String, List<Vulnerability>>()
    val containerScanRepositories = mutableMapOf<String, ContainerScanStats>()

    runBlocking {
        launch {
            listRepos(apolloClient, repositoryChannel)
            repositoryChannel.close()
        }

        launch {
            for (r in repositoryChannel) {
                repositories.add(r)

                launch {
                    val vulnerabilities = getVulnerabilitiesForRepo(apolloClient, r.name)
                    if (vulnerabilities.isNotEmpty()) {
                        r.copy(vulnerabilities = vulnerabilities).let {
                            logger.info("${vulnerabilities.size} sårbarheter i ${r.name}")
                            vulnRepositories[it.name] = vulnerabilities
                        }
                    }
                }

                if (POSSIBLE_CONTAINER_SCAN.contains(r.language)) {
                    launch {
                        try {
                            val containerScanStats = getContainerScanStats(githubApiClient, r)
                            if (containerScanStats != null) {
                                r.copy(containerScanStats = containerScanStats).let {
                                    logger.info("${r.name} ${if (containerScanStats.passes) "passerer" else "feiler"} containerscan, ${containerScanStats.passPercentage}% suksess siste ${daysToCount} dager (${containerScanStats.numberOfRuns} kjøringer)")
                                   containerScanRepositories[it.name] = containerScanStats
                                }
                            } else {
                                logger.info("${r.name} har ikke containerscan-workflow, skipper")
                            }
                        } catch (e: IOException) {
                            logger.warn("IOException ved henting av container scans", e)
                        }
                    }
                }
            }
        }
    }

    val repos: List<Repository> = repositories.map { it.copy(vulnerabilities = vulnRepositories[it.name] ?: it.vulnerabilities, containerScanStats = containerScanRepositories[it.name] ?: it.containerScanStats) }
    return Repos(repos)
}

private fun getContainerScanStats(
    githubApiClient: GithubApiClient,
    repo: Repository
): ContainerScanStats? {
    val runs: List<WorkflowRun> = githubApiClient.fetchWorkflowRuns(repo, daysToCount)
    if (runs.isEmpty()) return null
    val total: Int = runs.size
    val passed: Int = runs.filter { it.isSuccess() }.size
    return ContainerScanStats(runs.first().isSuccess(), "%.1f".format((passed.toDouble() * 100 / total)).toDouble(), total)
}


private suspend fun getVulnerabilitiesForRepo(
    apolloClient: ApolloClient,
    name: String
): List<Vulnerability> {
    if (logger.isDebugEnabled) logger.debug("henter sårbarheter for repo $name")
    val response = apolloClient.query(GetVulnerabilityAlertsForRepoQuery(name, "digipost")).execute()

    val vulnerabilityAlerts = response.data?.repository?.vulnerabilityAlerts?.nodes ?: emptyList()
    val vulnerabilities = vulnerabilityAlerts.mapNotNull {
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


private suspend fun listRepos(apolloClient: ApolloClient, repositoryChannel: Channel<Repository>) {
    if (logger.isDebugEnabled) logger.debug("Henter repoer med owner 'digipost' som ikke er arkiverte og har språk i listen $LANGUAGES")

    var cursor: String? = null
    var hasNext = true

    while (hasNext) {
        if (logger.isDebugEnabled) logger.debug("henter repoer fra Github ${if (cursor != null) " etter: $cursor" else " fra toppen"}")

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
}
