package no.digipost.github.monitoring

import com.apollographql.apollo3.ApolloClient
import com.apollographql.apollo3.api.Optional
import com.github.graphql.client.GetVulnerabilityAlertsForRepoQuery
import com.github.graphql.client.QueryRepositoriesQuery
import kotlinx.coroutines.runBlocking
import okhttp3.internal.toImmutableList
import java.time.ZonedDateTime

data class Repos(val all: List<Repository>, val onlyVulnerable: List<Repository>)

fun fetchAllReposWithVulnerabilities(apolloClient: ApolloClient): Repos {
    return runBlocking {
        return@runBlocking listRepos(apolloClient)
            .map { r ->
                val vulnerabilities = getVulnerabilitiesForRepo(apolloClient, r.name)
                r.copy(vulnerabilities = vulnerabilities)
            }.map { Repos(listOf(it), listOf(it)) }
            .reduce { acc, repos -> Repos(acc.all.plus(repos.all), acc.onlyVulnerable.plus(repos.onlyVulnerable)) }
    }
}


private suspend fun getVulnerabilitiesForRepo(
    apolloClient: ApolloClient,
    name: String
): List<Vulnerability?> {
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

    return vulnerabilities;
}


private suspend fun listRepos(apolloClient: ApolloClient): List<Repository> {
    println("Henter repoer")

    val mutableListOf = mutableListOf<Repository>()

    var cursor: String? = null
    var hasNext = true

    while (hasNext) {
        val response = apolloClient.query(QueryRepositoriesQuery(Optional.Present(cursor))).execute()

        response.data?.viewer?.repositories?.nodes
            ?.filter { "digipost" == it?.owner?.login && !it.isArchived }
            ?.filter { LANGUAGES.contains(it?.languages?.nodes?.firstOrNull()?.name) }
            ?.forEach {
                it?.let {
                    mutableListOf.add(
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
