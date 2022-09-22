package no.digipost.github.monitoring

import com.apollographql.apollo3.ApolloClient
import com.apollographql.apollo3.api.http.HttpHeader
import io.micrometer.core.instrument.MultiGauge
import io.micrometer.core.instrument.Tags
import io.micrometer.prometheus.PrometheusConfig
import io.micrometer.prometheus.PrometheusMeterRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import no.digipost.monitoring.micrometer.ApplicationInfoMetrics
import no.digipost.monitoring.prometheus.SimplePrometheusServer
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path
import kotlin.system.measureTimeMillis

val LANGUAGES = setOf("JavaScript", "Java", "TypeScript", "C#", "Kotlin", "Go")

suspend fun main(): Unit = coroutineScope {
    val env = System.getenv("env")
    val token = if (env == "local") System.getenv("token") else withContext(Dispatchers.IO) {
        Files.readString(Path.of("/secrets/githubtoken.txt")).trim()
    }

    val logger = LoggerFactory.getLogger("no.digipost.github.monitoring.Main")
    val prometheusMeterRegistry = PrometheusMeterRegistry(PrometheusConfig.DEFAULT)

    ApplicationInfoMetrics().bindTo(prometheusMeterRegistry)

    val multiGaugeRepoVulnCount = MultiGauge.builder("repository_vulnerability_count")
        .tags("owner", "digipost")
        .register(prometheusMeterRegistry)

    val multiGaugeInfoScore = MultiGauge.builder("vulnerability_info_score")
        .tags("owner", "digipost")
        .register(prometheusMeterRegistry)

    val apolloClient = ApolloClient.Builder()
        .httpHeaders(listOf(HttpHeader("Authorization", "bearer $token")))
        .serverUrl("https://api.github.com/graphql")
        .build()

    launch {
        while (isActive) {
            val timeMillis = measureTimeMillis {
                publish(apolloClient, multiGaugeRepoVulnCount, multiGaugeInfoScore)
            }
            logger.info("Henting av repos med sårbarheter tok ${timeMillis}ms")
            delay(1000 * 60 * 5)
        }
    }


    SimplePrometheusServer(logger::info)
        .startMetricsServer(prometheusMeterRegistry, 9610)
}

suspend fun publish(apolloClient: ApolloClient, registerRepos: MultiGauge, registerVulnerabilites: MultiGauge): Unit = coroutineScope {

    val channel = Channel<Repos>()
    launch {
        fetchAllReposWithVulnerabilities(apolloClient)
            .let { channel.send(it) }
    }

    launch {
        channel.receive().also { repos ->
            val (all, onlyVulnerable) = repos

            logger.info("Antall repos: ${all.size}")
            logger.info("Antall med sårbarheter: ${onlyVulnerable.size}")
            logger.info("Antall sårbarheter å rette: ${onlyVulnerable.flatMap { it.vulnerabilities }.count()}")

            all.map { repo ->
                MultiGauge.Row.of(Tags.of("name", repo.name, "language", repo.language), repo.vulnerabilities.size)
            }.let { registerRepos.register(it) }

            onlyVulnerable.map { repo ->
                repo.vulnerabilities.map { vuln ->
                    MultiGauge.Row.of(
                        Tags.of(
                            "name", repo.name,
                            "language", repo.language,
                            "CVE", vuln?.CVE ?: "",
                            "packagename", vuln?.packageName ?: "UNKNOWN",
                            "severity", vuln?.severity ?: "UNKNOWN",
                        ), vuln?.score ?: 0.0
                    )
                }
            }.flatMap { it.toList() }.let { registerVulnerabilites.register(it) }
        }
    }

}

